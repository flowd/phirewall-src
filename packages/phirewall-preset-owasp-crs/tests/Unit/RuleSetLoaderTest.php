<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Unit;

use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use Flowd\PhirewallPresetOwaspCrs\Tests\TemporaryFiles;
use PHPUnit\Framework\TestCase;

final class RuleSetLoaderTest extends TestCase
{
    use TemporaryFiles;

    private const LEVEL_ONE_RULES = 'SecRule ARGS "@rx union.*select" "id:942100,phase:2,block"' . "\n";

    /**
     * @return string The rules directory.
     */
    private function setUpRulesDirectory(): string
    {
        $this->temporaryFile('REQUEST-942-SQLI.pl1.conf', self::LEVEL_ONE_RULES);
        $this->temporaryFile('REQUEST-942-SQLI.pl2.conf', 'SecRule ARGS "@rx sleep\(" "id:942160,phase:2,block"' . "\n");
        $this->temporaryFile('REQUEST-941-XSS.pl3.conf', 'SecRule ARGS "@rx <script" "id:941100,phase:2,block"' . "\n");
        $this->temporaryFile('manifest.json', '{}');
        $this->temporaryFile('notes.txt', 'not a rule file');

        return $this->temporaryPath();
    }

    public function testSelectsOnlyFilesUpToTheRequestedParanoiaLevel(): void
    {
        $rulesDirectory = $this->setUpRulesDirectory();

        $ruleFiles = RuleSetLoader::ruleFiles(ParanoiaLevel::Level2, $rulesDirectory);

        $this->assertSame([
            $rulesDirectory . '/REQUEST-942-SQLI.pl1.conf',
            $rulesDirectory . '/REQUEST-942-SQLI.pl2.conf',
        ], $ruleFiles);
    }

    public function testLoadsCumulativeRuleSetForLevel(): void
    {
        $rulesDirectory = $this->setUpRulesDirectory();

        $levelOneRules = RuleSetLoader::load(ParanoiaLevel::Level1, $rulesDirectory);
        $this->assertSame([942100], $levelOneRules->ids());

        $levelThreeRules = RuleSetLoader::load(ParanoiaLevel::Level3, $rulesDirectory);
        $this->assertSame([941100, 942100, 942160], $levelThreeRules->ids());
    }

    public function testFailsForAMissingRulesDirectory(): void
    {
        $rulesDirectory = $this->setUpRulesDirectory();

        $this->expectException(\InvalidArgumentException::class);

        RuleSetLoader::ruleFiles(ParanoiaLevel::Level1, $rulesDirectory . '/missing');
    }

    public function testTheFingerprintOfAFileAskedAboutLastSeesItsChange(): void
    {
        $rulesDirectory = $this->setUpRulesDirectory();
        $this->assertFileExists($rulesDirectory . '/REQUEST-942-SQLI.pl1.conf');
        $ruleFile = $this->temporaryFile('REQUEST-942-SQLI.pl1.conf', self::LEVEL_ONE_RULES, 1_000_000);

        $files = [$ruleFile];
        $before = RuleSetLoader::fingerprint($files);

        // Another process gives the file a new time, which PHP does not see by
        // itself. No assertion before the second call: loading its class makes
        // PHP forget the file.
        $this->replaceFromAnotherProcess($ruleFile, self::LEVEL_ONE_RULES, 1_000_100);
        $after = RuleSetLoader::fingerprint($files);

        $this->assertNotSame($before, $after);
        $this->assertSame($after, RuleSetLoader::fingerprint($files));
    }
}
