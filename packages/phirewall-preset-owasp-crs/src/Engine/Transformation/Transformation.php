<?php

declare(strict_types=1);

namespace Flowd\PhirewallPresetOwaspCrs\Engine\Transformation;

/**
 * The transformations a rule can ask for with its `t:` actions. Each one
 * rewrites a collected value before the operator sees it, as ModSecurity
 * and Coraza do; where the two differ, this follows Coraza.
 *
 * `t:none` is no transformation: it empties the list of a rule, see
 * {@see TransformationPipeline}.
 */
enum Transformation: string
{
    case Base64Decode = 'base64decode';
    case Base64DecodeExt = 'base64decodeext';
    case Base64Encode = 'base64encode';
    case CmdLine = 'cmdline';
    case CompressWhitespace = 'compresswhitespace';
    case CssDecode = 'cssdecode';
    case EscapeSeqDecode = 'escapeseqdecode';
    case HexDecode = 'hexdecode';
    case HexEncode = 'hexencode';
    case HtmlEntityDecode = 'htmlentitydecode';
    case JsDecode = 'jsdecode';
    case Length = 'length';
    case Lowercase = 'lowercase';
    case Md5 = 'md5';
    case NormalisePath = 'normalisepath';
    case NormalisePathWin = 'normalisepathwin';
    case RemoveComments = 'removecomments';
    case RemoveCommentsChar = 'removecommentschar';
    case RemoveNulls = 'removenulls';
    case RemoveWhitespace = 'removewhitespace';
    case ReplaceComments = 'replacecomments';
    case ReplaceNulls = 'replacenulls';
    case Sha1 = 'sha1';
    case SqlHexDecode = 'sqlhexdecode';
    case Trim = 'trim';
    case TrimLeft = 'trimleft';
    case TrimRight = 'trimright';
    case Uppercase = 'uppercase';
    case UrlDecode = 'urldecode';
    case UrlDecodeUni = 'urldecodeuni';
    case UrlEncode = 'urlencode';
    case Utf8ToUnicode = 'utf8tounicode';

    /** The name that empties the transformation list of a rule. */
    public const NONE = 'none';

    private const ALIASES = [
        'normalizepath' => 'normalisepath',
        'normalizepathwin' => 'normalisepathwin',
    ];

    /** What trim, trimLeft and trimRight take off. */
    private const TRIMMED = " \t\n\r\f\v";

    /**
     * The transformation of that name, without regard to case; null when the
     * engine has none of that name.
     */
    public static function tryFromName(string $name): ?self
    {
        $name = strtolower($name);

        return self::tryFrom(self::ALIASES[$name] ?? $name);
    }

    /**
     * Whether a `t:` action of that name can be honored: a transformation
     * of the engine, or `none`.
     */
    public static function isSupported(string $name): bool
    {
        return strtolower($name) === self::NONE || self::tryFromName($name) instanceof self;
    }

    /**
     * The bytes without which this transformation leaves a value as it is,
     * written as the inside of a character class that reads bytes; null when
     * it changes every value. A value may hold one of them and stay unchanged
     * all the same; one that holds none is sure to.
     */
    public function touchedBytes(): ?string
    {
        return match ($this) {
            self::UrlDecode, self::UrlDecodeUni => '%+',
            self::Utf8ToUnicode => '\x80-\xFF',
            self::HtmlEntityDecode => '&',
            self::JsDecode, self::CssDecode, self::EscapeSeqDecode => '\\\\',
            self::RemoveNulls, self::ReplaceNulls => '\x00',
            self::Lowercase => 'A-Z',
            self::Uppercase => 'a-z',
            self::CmdLine => '"\'\\\\^ ,;\t\r\n\/(A-Z',
            self::CompressWhitespace, self::RemoveWhitespace => '\t-\r \x80-\xFF',
            self::Trim, self::TrimLeft, self::TrimRight => '\t-\r ',
            self::NormalisePath => '.\/',
            self::NormalisePathWin => '.\/\\\\: ',
            self::ReplaceComments => '*',
            self::RemoveComments, self::RemoveCommentsChar => '*#\-',
            self::SqlHexDecode => 'xX',
            self::Base64Decode,
            self::Base64DecodeExt,
            self::Base64Encode,
            self::HexDecode,
            self::HexEncode,
            self::Length,
            self::Md5,
            self::Sha1,
            self::UrlEncode => null,
        };
    }

    public function apply(string $value): string
    {
        return match ($this) {
            self::Base64Decode => Base64::decode($value),
            self::Base64DecodeExt => Base64::decodeForgiving($value),
            self::Base64Encode => base64_encode($value),
            self::CmdLine => CommandLine::normalise($value),
            self::CompressWhitespace => Whitespace::compress($value),
            self::CssDecode => EscapeSequences::decodeCss($value),
            self::EscapeSeqDecode => EscapeSequences::decodeAnsiC($value),
            self::HexDecode => Hex::decode($value),
            self::HexEncode => bin2hex($value),
            self::HtmlEntityDecode => HtmlEntities::decode($value),
            self::JsDecode => EscapeSequences::decodeJavaScript($value),
            self::Length => (string) strlen($value),
            // Bytewise and ASCII only, as ModSecurity does it.
            self::Lowercase => strtolower($value),
            self::Md5 => md5($value, true),
            self::NormalisePath => Paths::normalise($value),
            self::NormalisePathWin => Paths::normaliseWindows($value),
            self::RemoveComments => Comments::remove($value),
            self::RemoveCommentsChar => Comments::removeMarkers($value),
            self::RemoveNulls => str_replace("\0", '', $value),
            self::RemoveWhitespace => Whitespace::remove($value),
            self::ReplaceComments => Comments::replace($value),
            self::ReplaceNulls => str_replace("\0", ' ', $value),
            self::Sha1 => sha1($value, true),
            self::SqlHexDecode => Hex::decodeSql($value),
            self::Trim => trim($value, self::TRIMMED),
            self::TrimLeft => ltrim($value, self::TRIMMED),
            self::TrimRight => rtrim($value, self::TRIMMED),
            self::Uppercase => strtoupper($value),
            self::UrlDecode => UrlCoding::decode($value),
            self::UrlDecodeUni => UrlCoding::decodeUnicode($value),
            self::UrlEncode => UrlCoding::encode($value),
            self::Utf8ToUnicode => UrlCoding::utf8ToUnicode($value),
        };
    }
}
