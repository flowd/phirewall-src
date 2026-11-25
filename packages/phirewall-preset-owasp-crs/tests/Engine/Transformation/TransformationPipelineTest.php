<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Tests\Engine\Transformation;

use Flowd\PhirewallPresetOwaspCrs\Engine\Transformation\TransformationPipeline;
use PHPUnit\Framework\TestCase;

final class TransformationPipelineTest extends TestCase
{
    public function testAppliesTheTransformationsInTheOrderGiven(): void
    {
        $decodeThenLowercase = $this->pipeline(['urlDecodeUni', 'lowercase']);
        $lowercaseThenDecode = $this->pipeline(['lowercase', 'urlDecodeUni']);

        $this->assertSame('a', $decodeThenLowercase->apply('%41'));
        $this->assertSame('A', $lowercaseThenDecode->apply('%41'));
    }

    public function testNoneDropsWhatIsListedBeforeIt(): void
    {
        $transformationPipeline = $this->pipeline(['lowercase', 'none', 'urlDecodeUni']);

        $this->assertSame('A', $transformationPipeline->apply('%41'));
        $this->assertSame('urldecodeuni', $transformationPipeline->key);
    }

    public function testWithoutTransformationsTheValueStays(): void
    {
        foreach ([[], ['none'], ['lowercase', 'NONE']] as $names) {
            $transformationPipeline = $this->pipeline($names);

            $this->assertTrue($transformationPipeline->isEmpty());
            $this->assertSame('%41', $transformationPipeline->apply('%41'));
            $this->assertSame(['%41'], $transformationPipeline->stages('%41'));
        }
    }

    public function testAnUnsupportedNameMakesNoPipeline(): void
    {
        $this->assertNotInstanceOf(TransformationPipeline::class, TransformationPipeline::fromNames(['urlDecodeUni', 'parityEven7bit']));
        // Not even when "none" follows: the rule is not one the engine can read.
        $this->assertNotInstanceOf(TransformationPipeline::class, TransformationPipeline::fromNames(['parityEven7bit', 'none']));
    }

    public function testTheKeyNamesTheTransformationsHoweverTheyAreSpelled(): void
    {
        $this->assertSame(
            $this->pipeline(['urlDecodeUni', 'normalizePath'])->key,
            $this->pipeline(['none', 'URLDECODEUNI', 'normalisePath'])->key,
        );
        $this->assertNotSame(
            $this->pipeline(['urlDecodeUni', 'lowercase'])->key,
            $this->pipeline(['lowercase', 'urlDecodeUni'])->key,
        );
    }

    public function testADecodedByteThatIsNotUtf8IsReadAsTheCharacterOfItsNumber(): void
    {
        $transformationPipeline = $this->pipeline(['urlDecodeUni']);

        $this->assertSame('Müller', $transformationPipeline->apply('M%FCller'));
        // A well-formed sequence next to it is left as it is.
        $this->assertSame('üü', $transformationPipeline->apply('%C3%BC%FC'));
    }

    public function testBytesAreReadAsCharactersAfterTheLastTransformationOnly(): void
    {
        // The two halves of "ü" come out of two transformations.
        $this->assertSame('ü', $this->pipeline(['urlDecodeUni', 'jsDecode'])->apply('%C3\xBC'));
    }

    public function testNonAsciiSurvivesTheChainOfTheXssRules(): void
    {
        $transformationPipeline = $this->pipeline(['utf8toUnicode', 'urlDecodeUni', 'htmlEntityDecode', 'jsDecode', 'cssDecode', 'removeNulls']);

        $this->assertSame('Grüße aus Köln', $transformationPipeline->apply('Grüße aus Köln'));
        $this->assertSame('<script>', $transformationPipeline->apply('＜script＞'));
    }

    public function testAValueNoTransformationChangesIsReturnedAsItCame(): void
    {
        // Not UTF-8, and nothing to decode: the value is not rewritten.
        $this->assertSame("M\xFCller", $this->pipeline(['urlDecodeUni'])->apply("M\xFCller"));
    }

    public function testStagesAreTheValueAndEveryChangeToIt(): void
    {
        $transformationPipeline = $this->pipeline(['urlDecodeUni', 'removeNulls', 'htmlEntityDecode', 'lowercase']);

        $this->assertSame(
            ['%26lt;SCRIPT', '&lt;SCRIPT', '<SCRIPT', '<script'],
            $transformationPipeline->stages('%26lt;SCRIPT'),
        );
        $this->assertSame(['plain'], $transformationPipeline->stages('plain'));
    }

    public function testStagesThatAreNotUtf8AreReadAsCharactersToo(): void
    {
        $this->assertSame(['%FC%41', 'üA', 'üa'], $this->pipeline(['urlDecodeUni', 'lowercase'])->stages('%FC%41'));
    }

    /**
     * @param list<string> $names
     */
    private function pipeline(array $names): TransformationPipeline
    {
        $transformationPipeline = TransformationPipeline::fromNames($names);
        $this->assertInstanceOf(TransformationPipeline::class, $transformationPipeline);

        return $transformationPipeline;
    }
}
