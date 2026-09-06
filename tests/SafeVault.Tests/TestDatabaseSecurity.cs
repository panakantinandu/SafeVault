using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Web.Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestDatabaseSecurity
{
    private UserRepository _repository = null!;
    private string _dbPath = null!;

    [SetUp]
    public void SetUp()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"safevault_test_{Guid.NewGuid():N}.db");
        _repository = new UserRepository($"Data Source={_dbPath}");
        _repository.InitializeDatabase();
    }

    [TearDown]
    public void TearDown()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath))
        {
            File.Delete(_dbPath);
        }
    }

    [Test]
    public void AddUser_ValidInput_IsStoredAndRetrievable()
    {
        var created = _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");

        var fetched = _repository.GetUserByUsername("nandu_p");

        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched!.Email, Is.EqualTo("nandupanakanti@gmail.com"));
        Assert.That(fetched.UserId, Is.EqualTo(created.UserId));
    }

    [Test]
    public void AddUser_RejectsSqlInjectionPayloadBeforeHittingDatabase()
    {
        const string payload = "'; DROP TABLE Users; --";

        Assert.That(() => _repository.AddUser(payload, "user@example.com", "Str0ngPassw0rd!"),
            Throws.ArgumentException);

        // Table must survive: injection was neutralized by parameterization/validation.
        Assert.That(_repository.CountUsers(), Is.EqualTo(0));
    }

    [Test]
    public void AddUser_StoresSqlCommentSyntaxAsLiteralTextInsteadOfExecutingIt()
    {
        // "--" is a legal username character sequence (hyphens are allowlisted) and
        // also a SQL line-comment marker. This proves the parameterized query stores
        // it as inert literal data rather than truncating/altering the statement.
        const string username = "admin--";

        _repository.AddUser(username, "admin@example.com", "Str0ngPassw0rd!");

        var fetched = _repository.GetUserByUsername(username);
        Assert.That(fetched, Is.Not.Null);
        Assert.That(fetched!.Username, Is.EqualTo(username));
        Assert.That(_repository.CountUsers(), Is.EqualTo(1));
    }

    [Test]
    public void AddUser_DuplicateUsername_ThrowsInsteadOfSilentlyOverwriting()
    {
        _repository.AddUser("nandu_p", "first@example.com", "Str0ngPassw0rd!");

        Assert.That(() => _repository.AddUser("nandu_p", "second@example.com", "An0therPassw0rd!"),
            Throws.TypeOf<DuplicateUserException>());

        Assert.That(_repository.CountUsers(), Is.EqualTo(1));
    }

    [Test]
    public void AddUser_NeverStoresPasswordInPlaintext()
    {
        const string password = "Str0ngPassw0rd!";
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", password);

        using var connection = new SqliteConnection($"Data Source={_dbPath}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Username = 'nandu_p';";
        var storedHash = (string)command.ExecuteScalar()!;

        Assert.That(storedHash, Does.Not.Contain(password));
    }

    [Test]
    public void VerifyLogin_CorrectCredentials_ReturnsTrue()
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");

        Assert.That(_repository.VerifyLogin("nandu_p", "Str0ngPassw0rd!"), Is.True);
    }

    [Test]
    public void VerifyLogin_WrongPassword_ReturnsFalse()
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");

        Assert.That(_repository.VerifyLogin("nandu_p", "WrongPassword1"), Is.False);
    }

    [TestCase("' OR '1'='1")]
    [TestCase("nandu_p' --")]
    [TestCase("' OR 1=1 --")]
    public void VerifyLogin_SqlInjectionInUsername_ReturnsFalseInsteadOfBypassingAuth(string maliciousUsername)
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");

        Assert.That(_repository.VerifyLogin(maliciousUsername, "anything"), Is.False);
    }

    [Test]
    public void SearchUsersByUsername_FindsPartialMatch()
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");
        _repository.AddUser("other_user", "other@example.com", "An0therPassw0rd!");

        var results = _repository.SearchUsersByUsername("nandu");

        Assert.That(results.Select(u => u.Username), Is.EquivalentTo(new[] { "nandu_p" }));
    }

    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("' OR '1'='1")]
    [TestCase("%' OR '1'='1' --")]
    public void SearchUsersByUsername_SqlInjectionPayload_ReturnsNoResultsAndLeavesTableIntact(string payload)
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");

        var results = _repository.SearchUsersByUsername(payload);

        Assert.That(results, Is.Empty);
        Assert.That(_repository.CountUsers(), Is.EqualTo(1));
    }

    [Test]
    public void SearchUsersByUsername_LiteralWildcardCharacters_DoNotActAsWildcards()
    {
        _repository.AddUser("nandu_p", "nandupanakanti@gmail.com", "Str0ngPassw0rd!");
        _repository.AddUser("other_user", "other@example.com", "An0therPassw0rd!");

        // "%" and "_" are SQL LIKE wildcards; a naive implementation would match everything.
        var results = _repository.SearchUsersByUsername("%");

        Assert.That(results, Is.Empty);
    }
}
