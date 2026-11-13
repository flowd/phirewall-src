<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine;

use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;
use Flowd\PhirewallPresetOwaspCrs\Tests\TemporaryFiles;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class SecRuleLoaderTest extends TestCase
{
    use TemporaryFiles;

    public function testFromStringParsesMultilineSecRuleAndMatches(): void
    {
        $text = <<<'RULE'
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?i)<\?(?:[^x]|x(?:[^m]|m(?:[^l]|l(?:[^\s\x0b]|[\s\x0b]+[^a-z]|$)))|$|php)|\[[/\x5c]?php\]" \
    "id:933100,\
    phase:2,\
    block,\
    capture,\
    t:none,\
    msg:'PHP Injection Attack: PHP Open Tag Found',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-php',\
    tag:'platform-multi',\
    tag:'attack-injection-php',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'OWASP_CRS/ATTACK-PHP',\
    tag:'capec/1000/152/242',\
    ver:'OWASP_CRS/4.21.0-dev',\
    severity:'CRITICAL',\
    setvar:'tx.php_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
RULE;
        $coreRuleSet = SecRuleLoader::fromString($text);
        $req = new ServerRequest('GET', '/');
        $req = $req->withCookieParams(['a' => '<?php echo 1;']);
        $this->assertSame([933100], $coreRuleSet->evaluate($req)->matchedRuleIds());
    }

    public function testFromFileParsesMultilineSecRuleAndContainsId(): void
    {
        $root = dirname(__DIR__, 2);
        $path = $root . '/examples/05-secrule-files-rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf';
        $this->assertFileExists($path);
        $coreRuleSet = SecRuleLoader::fromFile($path);
        $this->assertContains(933100, $coreRuleSet->ids(), 'Expected multiline rule 933100 to be parsed from file');

        // And it should match request with PHP open tag in cookies
        $req = new ServerRequest('GET', '/');
        $req = $req->withCookieParams(['sess' => 'xx<?php yy']);
        $this->assertSame([933100], $coreRuleSet->evaluate($req)->matchedRuleIds());
    }

    public function testFromFileConfinesPmFromFileToRuleDirectory(): void
    {
        // A single-file load applies the same @pmFromFile confinement as
        // fromFiles()/fromDirectory(): an absolute operand is rejected rather than
        // silently read (arbitrary file read), and the rule fails closed (a
        // deterministic block) instead of throwing out of the matcher.
        $ruleFile = $this->temporaryFile('crs.conf', 'SecRule REQUEST_URI "@pmFromFile /etc/passwd" "id:730001,phase:2,deny"' . "\n");

        $coreRuleSet = SecRuleLoader::fromFile($ruleFile);

        $evaluation = $coreRuleSet->evaluate(new ServerRequest('GET', '/anything'));

        $this->assertTrue($evaluation->isBlocked());
        $this->assertTrue($evaluation->failClosed);
    }

    public function testFromStringWithReportCountsParsedAndSkipped(): void
    {
        $text = <<<'TXT'
# comment
SecRule REQUEST_URI "@contains admin" "id:700001,phase:2,deny"
invalid line
SecRule REQUEST_METHOD "@streq POST" "id:700002,phase:2,deny"
TXT;
        $result = SecRuleLoader::fromStringWithReport($text);
        $this->assertSame(2, $result['parsed']);
        // Comment lines are dropped during logical line building; only the truly invalid line is counted as skipped
        $this->assertSame(1, $result['skipped']);
        $this->assertSame([SecRuleLoader::SKIP_REASON_UNPARSEABLE => 1], $result['skippedByReason']);

        $rules = $result['rules'];
        $this->assertSame([700001], $rules->evaluate(new ServerRequest('GET', '/admin'))->matchedRuleIds());
        $this->assertSame([700002], $rules->evaluate(new ServerRequest('POST', '/x'))->matchedRuleIds());
    }

    public function testNonBlockingRuleMentioningBlockInItsMessageDoesNotBlock(): void
    {
        // Regression: the disruptive action used to fall back to a substring search over the
        // whole action list, so a "pass" rule whose msg contained "block" blocked.
        $coreRuleSet = SecRuleLoader::fromString(<<<'RULE'
SecRule ARGS "@rx foo" "id:700101,phase:2,pass,nolog,msg:'not blocking, just audit'"
SecRule ARGS "@rx foo" "id:700102,phase:2,log,tag:'deny-list'"
RULE);

        $evaluation = $coreRuleSet->evaluate((new ServerRequest('GET', '/?a=foo'))->withQueryParams(['a' => 'foo']));

        $this->assertFalse($evaluation->isBlocked());
        $this->assertSame([], $evaluation->matchedRuleIds());
    }

    public function testNegatedOperatorMatchesWhenTheOperatorDoesNot(): void
    {
        $result = SecRuleLoader::fromStringWithReport(
            'SecRule REQUEST_METHOD "!@rx ^(?:GET|POST)$" "id:700201,phase:1,deny,msg:\'Method not allowed\'"',
        );

        $this->assertSame(1, $result['parsed']);
        $this->assertSame([700201], $result['rules']->evaluate(new ServerRequest('PUT', '/'))->matchedRuleIds());
        $this->assertSame([], $result['rules']->evaluate(new ServerRequest('GET', '/'))->matchedRuleIds());
        $this->assertSame([], $result['rules']->evaluate(new ServerRequest('POST', '/'))->matchedRuleIds());
    }

    public function testNegatedOperatorSurvivesTheCompiledArtifactRoundTrip(): void
    {
        $rule = SecRuleLoader::fromString('SecRule REQUEST_METHOD "!@streq GET" "id:700202,phase:1,deny"')->getRule(700202);
        $this->assertInstanceOf(CoreRule::class, $rule);

        $hydrated = CoreRule::fromArray($rule->toArray());

        $this->assertTrue($hydrated->matches(new ServerRequest('DELETE', '/')));
        $this->assertFalse($hydrated->matches(new ServerRequest('GET', '/')));
    }

    public function testRuleWithUnsupportedOperatorIsSkippedAndReported(): void
    {
        // Loading it would yield a rule that silently never matches.
        $result = SecRuleLoader::fromStringWithReport(<<<'TXT'
SecRule REQUEST_HEADERS:X-Forwarded-For "@ipMatch 10.0.0.0/8" "id:700301,phase:1,deny"
SecRule REQUEST_HEADERS:X-Forwarded-For "!@ipMatch 10.0.0.0/8" "id:700302,phase:1,deny"
SecRule ARGS "@detectSQLi" "id:700303,phase:2,deny"
SecRule REQUEST_URI "@contains admin" "id:700304,phase:2,deny"
TXT);

        $this->assertSame(1, $result['parsed']);
        $this->assertSame(3, $result['skipped']);
        $this->assertSame(
            [SecRuleLoader::SKIP_REASON_UNSUPPORTED_OPERATOR => 2, SecRuleLoader::SKIP_REASON_UNPARSEABLE => 1],
            $result['skippedByReason'],
        );
        $this->assertSame([700304], $result['rules']->ids());
        $this->assertNotContains(700301, SecRuleLoader::fromString('SecRule ARGS "@ipMatch 10.0.0.0/8" "id:700301,deny"')->ids());
    }

    public function testFromFilesLoadsConcatenatedFiles(): void
    {
        $f1 = $this->temporaryFile('a.conf', "SecRule REQUEST_URI \"@contains a\" \"id:710001,phase:2,deny\"\n");
        $f2 = $this->temporaryFile('b.conf', "SecRule REQUEST_URI \"@contains b\" \"id:710002,phase:2,deny\"\n");

        $set = SecRuleLoader::fromFiles([$f1, $f2]);
        $this->assertSame([710001], $set->evaluate(new ServerRequest('GET', '/a'))->matchedRuleIds());
        $this->assertSame([710002], $set->evaluate(new ServerRequest('GET', '/b'))->matchedRuleIds());
    }

    public function testFromFilesThrowsOnMissingFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        SecRuleLoader::fromFiles(['/not/exist/file.conf']);
    }

    public function testFromDirectoryLoadsSortedAndRespectsFilter(): void
    {
        $this->temporaryFile('2.conf', "SecRule REQUEST_URI \"@contains two\" \"id:720002,phase:2,deny\"\n");
        $this->temporaryFile('1.conf', "SecRule REQUEST_URI \"@contains one\" \"id:720001,phase:2,deny\"\n");
        $this->temporaryFile('skip.txt', "SecRule REQUEST_URI \"@contains skip\" \"id:720999,phase:2,deny\"\n");

        $filter = static fn(string $path): bool => str_ends_with($path, '.conf');
        $set = SecRuleLoader::fromDirectory($this->temporaryPath(), $filter);

        // Sorted order means rule ids 720001 then 720002 are present; skip.txt ignored
        $this->assertSame([720001], $set->evaluate(new ServerRequest('GET', '/one'))->matchedRuleIds());
        $this->assertSame([720002], $set->evaluate(new ServerRequest('GET', '/two'))->matchedRuleIds());
        $this->assertSame([], $set->evaluate(new ServerRequest('GET', '/skip'))->matchedRuleIds());
    }
}
