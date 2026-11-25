<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * The transformations of one rule, in the order the rule lists them.
 */
final class TransformationPipeline
{
    /**
     * The pipelines made so far, by the names they were made from; null
     * for a list with a name that is not supported. Many rules list the
     * same transformations, and a pipeline has no state of its own.
     *
     * @var array<string, ?self>
     */
    private static array $byNames = [];

    /**
     * @param list<Transformation> $transformations
     * @param string $key Names the list: two pipelines with the same key turn a value into the same result.
     * @param ?string $touchedBytes A pattern for the bytes without which no transformation of the list
     *                              changes a value; null when one of them changes every value.
     */
    private function __construct(
        private readonly array $transformations,
        public readonly string $key,
        private readonly ?string $touchedBytes,
    ) {
    }

    /**
     * The pipeline for the `t:` actions of a rule. `none` drops everything
     * listed before it. Null when a name is not supported: the rule cannot
     * be evaluated as written.
     *
     * @param list<string> $names
     */
    public static function fromNames(array $names): ?self
    {
        $cacheKey = implode(',', $names);
        if (array_key_exists($cacheKey, self::$byNames)) {
            return self::$byNames[$cacheKey];
        }

        return self::$byNames[$cacheKey] = self::build($names);
    }

    /**
     * @param list<string> $names
     */
    private static function build(array $names): ?self
    {
        $transformations = [];
        foreach ($names as $name) {
            if (strtolower($name) === Transformation::NONE) {
                $transformations = [];
                continue;
            }

            $transformation = Transformation::tryFromName($name);
            if (!$transformation instanceof Transformation) {
                return null;
            }

            $transformations[] = $transformation;
        }

        $key = '';
        $touchedBytes = '';
        foreach ($transformations as $transformation) {
            $key .= ($key === '' ? '' : ',') . $transformation->value;
            $touchedByThis = $transformation->touchedBytes();
            $touchedBytes = $touchedBytes === null || $touchedByThis === null ? null : $touchedBytes . $touchedByThis;
        }

        return new self(
            $transformations,
            $key,
            $touchedBytes === null || $touchedBytes === '' ? null : '/[' . $touchedBytes . ']/',
        );
    }

    public function isEmpty(): bool
    {
        return $this->transformations === [];
    }

    /**
     * The value after all transformations.
     *
     * The transformations work on bytes. A result that is not UTF-8 is
     * read as {@see Utf8::fromBytes()} describes, because the operators
     * read UTF-8; a value no transformation changed is returned as it came.
     */
    public function apply(string $value): string
    {
        // Most values hold nothing any transformation of the list would touch.
        if ($this->touchedBytes !== null && preg_match($this->touchedBytes, $value) === 0) {
            return $value;
        }

        $result = $value;
        foreach ($this->transformations as $transformation) {
            $result = $transformation->apply($result);
        }

        if ($result === $value) {
            return $value;
        }

        return Utf8::isWellFormed($result) ? $result : Utf8::fromBytes($result);
    }

    /**
     * The value as it came and after every transformation that changed it:
     * what a `multiMatch` rule runs its operator against.
     *
     * @return list<string>
     */
    public function stages(string $value): array
    {
        if ($this->touchedBytes !== null && preg_match($this->touchedBytes, $value) === 0) {
            return [$value];
        }

        $stages = [$value];
        $current = $value;
        foreach ($this->transformations as $transformation) {
            $next = $transformation->apply($current);
            if ($next === $current) {
                continue;
            }

            $current = $next;
            $stages[] = Utf8::isWellFormed($current) ? $current : Utf8::fromBytes($current);
        }

        return $stages;
    }
}
