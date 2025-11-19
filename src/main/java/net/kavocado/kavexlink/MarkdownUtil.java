package net.kavocado.kavexlink;

import java.util.EnumSet;

public final class MarkdownUtil {

    private enum Style {
        BOLD, ITALIC, UNDERLINE, STRIKETHROUGH
    }

    private MarkdownUtil() {
    }

    public static String minecraftToDiscord(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }

        StringBuilder out = new StringBuilder();
        EnumSet<Style> active = EnumSet.noneOf(Style.class);

        char[] chars = input.toCharArray();
        int len = chars.length;

        for (int i = 0; i < len; i++) {
            char c = chars[i];

            // Handle & or § formatting codes
            if ((c == '&' || c == '§') && i + 1 < len) {
                char code = Character.toLowerCase(chars[++i]);

                EnumSet<Style> next = EnumSet.copyOf(active);

                switch (code) {
                    case 'l': // bold
                        toggle(next, Style.BOLD);
                        break;
                    case 'o': // italic
                        toggle(next, Style.ITALIC);
                        break;
                    case 'n': // underline
                        toggle(next, Style.UNDERLINE);
                        break;
                    case 'm': // strikethrough
                        toggle(next, Style.STRIKETHROUGH);
                        break;
                    case 'r': // reset
                        next.clear();
                        break;

                    // Colors (0-9, a-f) and obfuscated (&k): ignore for Discord
                    case 'k':
                    case '0': case '1': case '2': case '3':
                    case '4': case '5': case '6': case '7':
                    case '8': case '9':
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        // we only care about styles for Discord; colors are dropped
                        continue;

                    default:
                        // Not a known code: treat literally
                        out.append(c);
                        out.append(code);
                        continue;
                }

                if (!next.equals(active)) {
                    // Close old styles
                    out.append(closeMarkdown(active));
                    // Open new styles
                    out.append(openMarkdown(next));
                    active = next;
                }
            } else {
                out.append(c);
            }
        }

        // Close any remaining styles
        out.append(closeMarkdown(active));
        return out.toString();
    }

    private static void toggle(EnumSet<Style> set, Style style) {
        if (set.contains(style)) {
            set.remove(style);
        } else {
            set.add(style);
        }
    }

    private static String openMarkdown(EnumSet<Style> styles) {
        StringBuilder sb = new StringBuilder();
        // Fixed order so opening/closing is deterministic
        if (styles.contains(Style.UNDERLINE))     sb.append("__");
        if (styles.contains(Style.STRIKETHROUGH)) sb.append("~~");
        if (styles.contains(Style.BOLD))          sb.append("**");
        if (styles.contains(Style.ITALIC))        sb.append("*");
        return sb.toString();
    }

    private static String closeMarkdown(EnumSet<Style> styles) {
        StringBuilder sb = new StringBuilder();
        // Reverse order of openMarkdown
        if (styles.contains(Style.ITALIC))        sb.append("*");
        if (styles.contains(Style.BOLD))          sb.append("**");
        if (styles.contains(Style.STRIKETHROUGH)) sb.append("~~");
        if (styles.contains(Style.UNDERLINE))     sb.append("__");
        return sb.toString();
    }
}

