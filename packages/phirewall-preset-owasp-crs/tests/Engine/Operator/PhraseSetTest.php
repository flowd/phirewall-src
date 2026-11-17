<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Operator;

use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\OperatorResult;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\PhraseMatchEvaluator;
use Flowd\PhirewallPresetOwaspCrs\Engine\Operator\PhraseSet;
use Flowd\PhirewallPresetOwaspCrs\Engine\RuleOutcome;
use Flowd\PhirewallPresetOwaspCrs\RuleSetLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The prefilter must never change what a phrase operator finds: with it, a
 * set reports the same value and the same phrase as the search phrase by
 * phrase, which stays the reference here.
 */
final class PhraseSetTest extends TestCase
{
    /**
     * @param list<string> $phrases
     * @param list<string> $values
     */
    private function assertSameAsPhraseByPhrase(array $phrases, array $values, string $message = ''): void
    {
        $phraseSet = PhraseSet::compile($phrases);
        foreach ($values as $value) {
            $expected = PhraseMatchEvaluator::firstMatch([$value], $phrases);
            $actual = $phraseSet->firstMatch([$value]);

            $this->assertSame(
                [$expected->outcome, $expected->matchedValueIndex, $expected->captures],
                [$actual->outcome, $actual->matchedValueIndex, $actual->captures],
                sprintf('%s value %s', $message, bin2hex($value)),
            );
        }
    }

    public function testACompiledSetHasAPrefilter(): void
    {
        $phraseSet = PhraseSet::compile(['/etc/passwd', '/etc/shadow']);

        $this->assertSame('~/etc/(?:passwd|shadow)~', $phraseSet->prefilter);
        $this->assertNull(PhraseSet::withoutPrefilter(['/etc/passwd'])->prefilter);
    }

    public function testMatchingIgnoresAsciiCaseOnBothSides(): void
    {
        $phraseSet = PhraseSet::compile(['SeCrEt', 'admin']);

        $this->assertSame(['SeCrEt'], $phraseSet->firstMatch(['my SECRET value'])->captures);
        $this->assertSame(['admin'], $phraseSet->firstMatch(['/Admin/'])->captures);
        $this->assertSame(RuleOutcome::NoMatch, $phraseSet->firstMatch(['nothing here'])->outcome);
    }

    public function testTheFirstPhraseInListOrderIsReported(): void
    {
        // "abc" occurs further left in the value, "bc" comes first in the list.
        $phraseSet = PhraseSet::compile(['bc', 'abc']);

        $this->assertSame(['bc'], $phraseSet->firstMatch(['xabcx'])->captures);
    }

    public function testTheFirstValueWithAPhraseIsReported(): void
    {
        $operatorResult = PhraseSet::compile(['needle'])->firstMatch(['hay', 'more hay', 'a NEEDLE', 'needle again']);

        $this->assertSame(2, $operatorResult->matchedValueIndex);
    }

    public function testAPhraseThatStartsWithAnotherIsStillReportedWhenItComesFirst(): void
    {
        // The prefilter leaves "passwd.bak" out (wherever it occurs, "passwd" does too);
        // the report must not depend on that.
        $this->assertSame(['passwd.bak'], PhraseSet::compile(['passwd.bak', 'passwd'])->firstMatch(['/etc/passwd.bak'])->captures);
        $this->assertSame(['passwd'], PhraseSet::compile(['passwd.bak', 'passwd'])->firstMatch(['/etc/passwd'])->captures);
        $this->assertSame(['passwd'], PhraseSet::compile(['passwd', 'passwd.bak'])->firstMatch(['/etc/passwd.bak'])->captures);
    }

    public function testEmptyListsAndEmptyPhrasesNeverMatch(): void
    {
        $this->assertSame(RuleOutcome::NoMatch, PhraseSet::compile([])->firstMatch(['anything'])->outcome);
        $this->assertNull(PhraseSet::compile([])->prefilter);
        $this->assertNull(PhraseSet::compile([''])->prefilter);
        $this->assertSame(RuleOutcome::NoMatch, PhraseSet::compile([''])->firstMatch(['anything', ''])->outcome);
        $this->assertSame(['b'], PhraseSet::compile(['', 'b'])->firstMatch(['abc'])->captures);
    }

    public function testPhrasesAreTakenLiterally(): void
    {
        $phrases = ['a.c', '(x|y)', '[a-z]+', 'tilde~here', 'back\\slash', '$_GET', 'two  spaces', '#hash', '^start', 'end$', '1', '0day', "nul\0byte", "\xC3\x84", "tab\there", '?', '*', '{2}', '\\d'];
        $values = ['abc', 'a.c', 'A.C', 'x', '(X|Y)', 'q', '[a-z]+', 'tilde~here', 'back\\slash', 'backslash', '$_get', 'two spaces', 'two  spaces', '#HASH', '^START', 'END$', '1', '0', '0DAY', "nul\0byte", "nulbyte", "\xC3\x84", "\xC3\xA4", "\xC3", "tab\there", 'tab here', '', '?', '*', '{2}', '22', '\\d', '5', "line\nbreak a.c"];

        $this->assertSameAsPhraseByPhrase($phrases, $values);
        foreach ($phrases as $phrase) {
            // Each on its own, so that no other phrase can stand in for it.
            $this->assertSameAsPhraseByPhrase([$phrase], $values, 'phrase ' . bin2hex($phrase));
        }
    }

    public function testBytesOutsideAsciiAreNotCaseFolded(): void
    {
        // stripos() folds ASCII letters only; "Ä" (C3 84) and "ä" (C3 A4) differ.
        $phraseSet = PhraseSet::compile(["\xC3\x84rger"]);

        $this->assertSame(RuleOutcome::Matched, $phraseSet->firstMatch(["\xC3\x84RGER"])->outcome);
        $this->assertSame(RuleOutcome::NoMatch, $phraseSet->firstMatch(["\xC3\xA4rger"])->outcome);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function shippedPhraseFiles(): iterable
    {
        foreach (RuleSetLoader::dataFiles(RuleSetLoader::defaultRulesDirectory()) as $dataFile) {
            yield basename($dataFile) => [$dataFile];
        }
    }

    #[DataProvider('shippedPhraseFiles')]
    public function testShippedPhraseFilesGiveTheSameAnswersWithThePrefilter(string $dataFile): void
    {
        $phrases = [];
        foreach (preg_split('/\r?\n/', (string) file_get_contents($dataFile)) ?: [] as $line) {
            $line = trim($line);
            if ($line !== '' && !str_starts_with($line, '#')) {
                $phrases[$line] = $line;
            }
        }

        $phrases = array_values($phrases);
        $this->assertNotSame([], $phrases);
        $this->assertNotNull(PhraseSet::compile($phrases)->prefilter, 'The shipped lists are expected to compile into a prefilter.');

        mt_srand(20261116);
        $values = ['', 'q=shoes&page=2', 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr.'];
        foreach ($phrases as $position => $phrase) {
            $values[] = $phrase;
            if ($position % 3 === 0) {
                $values[] = 'x' . strtoupper($phrase) . 'y';
                $values[] = ucfirst($phrase);
            }

            if ($position % 5 === 0) {
                // Almost a phrase: these must not be found unless another phrase is.
                $values[] = substr($phrase, 0, -1);
                $values[] = substr($phrase, 1);
                $values[] = substr($phrase, 0, intdiv(strlen($phrase), 2)) . ' ' . substr($phrase, intdiv(strlen($phrase), 2));
            }
        }

        for ($i = 0; $i < 400; ++$i) {
            $values[] = substr(base64_encode(random_bytes(48)), 0, mt_rand(1, 60));
            $values[] = random_bytes(mt_rand(1, 24));
        }

        $this->assertSameAsPhraseByPhrase($phrases, $values, basename($dataFile));
    }

    public function testRandomPhraseListsGiveTheSameAnswersWithThePrefilter(): void
    {
        mt_srand(4711);
        $alphabet = ['a', 'b', 'A', 'B', '.', '/', '1', '(', '|'];
        $word = static function (int $maxLength) use ($alphabet): string {
            $word = '';
            for ($i = mt_rand(1, $maxLength); $i > 0; --$i) {
                $word .= $alphabet[mt_rand(0, count($alphabet) - 1)];
            }

            return $word;
        };

        for ($round = 0; $round < 150; ++$round) {
            $phrases = [];
            for ($i = mt_rand(1, 12); $i > 0; --$i) {
                $phrases[] = $word(4);
            }

            $phrases = array_values(array_unique($phrases));
            $values = [];
            for ($i = 0; $i < 60; ++$i) {
                $values[] = $word(7);
            }

            $this->assertSameAsPhraseByPhrase($phrases, $values, 'phrases ' . json_encode($phrases));
        }
    }

    public function testAValueThePrefilterCannotJudgeIsSearchedPhraseByPhrase(): void
    {
        $jit = ini_get('pcre.jit');
        $backtrackLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.jit', '0');
        try {
            // A list no other test uses, so the expression is compiled for the interpreter, where the limit applies.
            $phraseSet = PhraseSet::compile(['fallback-' . bin2hex(random_bytes(4)), 'needle-in-the-hay', 'nnx', 'nny']);
            $this->assertNotNull($phraseSet->prefilter);

            ini_set('pcre.backtrack_limit', '1');
            $value = str_repeat('n', 200) . ' needle-in-the-hay';
            $this->assertFalse(@preg_match((string) $phraseSet->prefilter, $value), 'The expression is expected to hit the limit here.');
            $this->assertSame(['needle-in-the-hay'], $phraseSet->firstMatch([$value])->captures);

            // Under the limit even the check on an empty text may fail; that is not "does not compile".
            $this->assertNotNull(PhraseSet::fromArray($phraseSet->toArray())->prefilter);
        } finally {
            ini_set('pcre.jit', (string) $jit);
            ini_set('pcre.backtrack_limit', (string) $backtrackLimit);
        }
    }

    public function testAListTooLargeForOneExpressionWorksWithoutPrefilter(): void
    {
        mt_srand(99);
        $phrases = [];
        for ($i = 0; $i < 5000; ++$i) {
            $phrases[] = bin2hex(random_bytes(40));
        }

        $phraseSet = PhraseSet::compile($phrases);

        $this->assertNull($phraseSet->prefilter, 'A list of this size gets no prefilter.');
        $this->assertSame([$phrases[4999]], $phraseSet->firstMatch(['x' . strtoupper($phrases[4999])])->captures);
        $this->assertSame(RuleOutcome::NoMatch, $phraseSet->firstMatch(['nothing'])->outcome);
    }

    public function testAListThatDoesNotCompileRaisesNothing(): void
    {
        mt_srand(7);
        $phrases = [];
        for ($i = 0; $i < 2000; ++$i) {
            $phrases[] = bin2hex(random_bytes(15));
        }

        // An application that turns every warning into an exception, also the silenced ones.
        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });

        try {
            $phraseSet = PhraseSet::compile($phrases);
            $restored = PhraseSet::fromArray(['phrases' => ['alpha'], 'prefilter' => '~(unbalanced~']);
            $found = $phraseSet->firstMatch(['x' . $phrases[1999] . 'y'])->captures;
        } finally {
            restore_error_handler();
        }

        $this->assertNull($phraseSet->prefilter, 'An expression for this list is not expected to compile.');
        $this->assertNull($restored->prefilter);
        $this->assertSame([$phrases[1999]], $found);
    }

    public function testPhrasesWithALongCommonBeginningAreCheapToCompile(): void
    {
        $phrases = [];
        for ($i = 0; $i < 5000; ++$i) {
            $phrases[] = str_repeat('a', 2000) . $i;
        }

        $before = memory_get_usage();
        memory_reset_peak_usage();
        $phraseSet = PhraseSet::compile($phrases);

        $this->assertLessThan(16 * 1024 * 1024, memory_get_peak_usage() - $before);
        $this->assertSame([$phrases[7]], $phraseSet->firstMatch([strtoupper($phrases[7])])->captures);
        $this->assertSameAsPhraseByPhrase($phrases, [$phrases[4999], $phrases[17], substr($phrases[17], 1), str_repeat('a', 2000), 'nothing']);
    }

    public function testTheOrderOfThePhrasesDoesNotChangeThePrefilter(): void
    {
        $this->assertSame(
            PhraseSet::compile(['/etc/shadow', '/bin/sh', '/etc/passwd', '/ETC/PASSWD', '/etc'])->prefilter,
            PhraseSet::compile(['/etc', '/etc/passwd', '/bin/sh', '/etc/shadow'])->prefilter,
        );
        $this->assertSame('~/(?:bin/sh|etc)~', PhraseSet::compile(['/etc/shadow', '/bin/sh', '/etc'])->prefilter);
    }

    public function testRoundTripThroughCompiledData(): void
    {
        $phraseSet = PhraseSet::compile(['alpha', 'beta']);
        $restored = PhraseSet::fromArray($phraseSet->toArray());

        $this->assertSame($phraseSet->toArray(), $restored->toArray());
        $this->assertSame(['beta'], $restored->firstMatch(['BETA'])->captures);
    }

    public function testAPrefilterThatDoesNotCompileIsDropped(): void
    {
        $restored = PhraseSet::fromArray(['phrases' => ['alpha'], 'prefilter' => '~(unbalanced~']);

        $this->assertNull($restored->prefilter);
        $this->assertSame(['alpha'], $restored->firstMatch(['ALPHA'])->captures);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function malformedData(): iterable
    {
        yield 'not an array' => ['alpha'];
        yield 'no phrases' => [['prefilter' => null]];
        yield 'phrases not a list' => [['phrases' => ['a' => 'alpha'], 'prefilter' => null]];
        yield 'phrase not a string' => [['phrases' => ['alpha', 5], 'prefilter' => null]];
        yield 'prefilter not a string' => [['phrases' => ['alpha'], 'prefilter' => 5]];
    }

    #[DataProvider('malformedData')]
    public function testMalformedCompiledDataIsRejected(mixed $data): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PhraseSet::fromArray($data);
    }

    public function testNoMatchIsTheSharedResult(): void
    {
        $this->assertSame(OperatorResult::noMatch(), PhraseSet::compile(['a'])->firstMatch(['b']));
    }
}
