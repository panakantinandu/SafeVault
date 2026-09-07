using System.Text.Encodings.Web;
using System.Text.RegularExpressions;

namespace SafeVault.Web.Validation;

public static class InputValidator
{
    private static readonly Regex UsernamePattern = new(
        @"^[A-Za-z0-9_\-\.]{3,30}$",
        RegexOptions.Compiled);

    private static readonly Regex EmailPattern = new(
        @"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
        RegexOptions.Compiled);

    public static bool IsValidUsername(string? username)
    {
        return !string.IsNullOrWhiteSpace(username) && UsernamePattern.IsMatch(username);
    }

    public static bool IsValidEmail(string? email)
    {
        return !string.IsNullOrWhiteSpace(email)
            && email.Length <= 100
            && EmailPattern.IsMatch(email);
    }

    public static bool IsValidPassword(string? password)
    {
        return !string.IsNullOrEmpty(password) && password.Length is >= 8 and <= 128;
    }

    private static readonly HashSet<string> AllowedRoles = new(StringComparer.Ordinal) { "user", "admin" };

    public static bool IsValidRole(string? role) => role is not null && AllowedRoles.Contains(role);

    public static string EncodeForHtml(string input) => HtmlEncoder.Default.Encode(input);

    // Defense-in-depth only: parameterized queries and EncodeForHtml remain the real defenses.
    private static readonly Regex UsernameSanitizePattern = new(@"[^A-Za-z0-9_\-\.]", RegexOptions.Compiled);
    private static readonly Regex EmailSanitizePattern = new(@"[^A-Za-z0-9._%+\-@]", RegexOptions.Compiled);
    private static readonly Regex SearchTermSanitizePattern = new(@"[^A-Za-z0-9 _\-\.]", RegexOptions.Compiled);

    public static string SanitizeUsername(string? input) =>
        UsernameSanitizePattern.Replace(input ?? string.Empty, string.Empty);

    public static string SanitizeEmail(string? input) =>
        EmailSanitizePattern.Replace(input ?? string.Empty, string.Empty);

    public static string SanitizeSearchTerm(string? input) =>
        SearchTermSanitizePattern.Replace(input ?? string.Empty, string.Empty);
}
