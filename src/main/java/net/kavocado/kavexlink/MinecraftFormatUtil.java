package net.kavocado.kavexlink;

public final class MinecraftFormatUtil {

    private MinecraftFormatUtil() {}

    /**
     * Convert &-codes to §-codes, but keep style codes (l, o, n, m, k)
     * logically "active" across color changes by re-applying them after
     * every color code.
     *
     * Example: "&n&4Cross" -> "§n§4§nCross"
     * so that underline stays even though §4 normally resets styles.
     */
    public static String applyPersistentFormatting(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        StringBuilder out = new StringBuilder();

        boolean bold = false;
        boolean italic = false;
        boolean under = false;
        boolean strike = false;
        boolean obfus = false;

        int len = input.length();
        for (int i = 0; i < len; i++) {
            char c = input.charAt(i);

            if ((c == '&' || c == '§') && i + 1 < len) {
                char code = Character.toLowerCase(input.charAt(++i));

                switch (code) {
                    // reset
                    case 'r':
                        bold = italic = under = strike = obfus = false;
                        out.append('§').append('r');
                        break;

                    // style codes turn styles ON and emit them
                    case 'l': // bold
                        bold = true;
                        out.append('§').append('l');
                        break;
                    case 'o': // italic
                        italic = true;
                        out.append('§').append('o');
                        break;
                    case 'n': // underline
                        under = true;
                        out.append('§').append('n');
                        break;
                    case 'm': // strikethrough
                        strike = true;
                        out.append('§').append('m');
                        break;
                    case 'k': // obfuscated
                        obfus = true;
                        out.append('§').append('k');
                        break;

                    // colors: emit the color, then re-emit any active styles
                    case '0': case '1': case '2': case '3':
                    case '4': case '5': case '6': case '7':
                    case '8': case '9':
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        out.append('§').append(code);
                        if (bold)   out.append('§').append('l');
                        if (italic) out.append('§').append('o');
                        if (under)  out.append('§').append('n');
                        if (strike) out.append('§').append('m');
                        if (obfus)  out.append('§').append('k');
                        break;

                    default:
                        // unknown -> literal
                        out.append(c).append(code);
                        break;
                }
            } else {
                out.append(c);
            }
        }

        return out.toString();
    }
}

