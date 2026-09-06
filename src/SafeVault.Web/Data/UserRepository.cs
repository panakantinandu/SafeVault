using Microsoft.Data.Sqlite;
using SafeVault.Web.Security;
using SafeVault.Web.Validation;

namespace SafeVault.Web.Data;

public record UserRecord(int UserId, string Username, string Email);

public class DuplicateUserException : Exception
{
    public DuplicateUserException(string message) : base(message) { }
}

public class UserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public void InitializeDatabase()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE,
                Email TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL
            );";
        command.ExecuteNonQuery();
    }

    public UserRecord AddUser(string username, string email, string password)
    {
        if (!InputValidator.IsValidUsername(username))
        {
            throw new ArgumentException("Invalid username.", nameof(username));
        }

        if (!InputValidator.IsValidEmail(email))
        {
            throw new ArgumentException("Invalid email.", nameof(email));
        }

        if (!InputValidator.IsValidPassword(password))
        {
            throw new ArgumentException("Password must be 8-128 characters.", nameof(password));
        }

        var passwordHash = PasswordHasher.Hash(password);

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO Users (Username, Email, PasswordHash)
            VALUES ($username, $email, $passwordHash);
            SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);

        try
        {
            var newId = (long)command.ExecuteScalar()!;
            return new UserRecord((int)newId, username, email);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
        {
            throw new DuplicateUserException($"Username '{username}' or email '{email}' already exists.");
        }
    }

    // Parameterized credential lookup: the username placeholder prevents SQL injection,
    // and the password is never compared or stored in plaintext (see PasswordHasher).
    public bool VerifyLogin(string username, string password)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        var storedHash = command.ExecuteScalar() as string;
        return storedHash is not null && PasswordHasher.Verify(password, storedHash);
    }

    // Parameterized LIKE search: the search term is bound as a parameter, so wildcard/
    // injection characters in user input are treated as literal text, not query syntax.
    public List<UserRecord> SearchUsersByUsername(string searchTerm)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username LIKE $pattern ESCAPE '\\';";
        var escaped = searchTerm.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        command.Parameters.AddWithValue("$pattern", $"%{escaped}%");

        using var reader = command.ExecuteReader();
        var results = new List<UserRecord>();
        while (reader.Read())
        {
            results.Add(new UserRecord(reader.GetInt32(0), reader.GetString(1), reader.GetString(2)));
        }

        return results;
    }

    public UserRecord? GetUserByUsername(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return new UserRecord(reader.GetInt32(0), reader.GetString(1), reader.GetString(2));
        }

        return null;
    }

    public int CountUsers()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM Users;";
        return Convert.ToInt32(command.ExecuteScalar());
    }
}
