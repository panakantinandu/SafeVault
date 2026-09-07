using Microsoft.Data.Sqlite;
using SafeVault.Web.Security;
using SafeVault.Web.Validation;

namespace SafeVault.Web.Data;

public record UserRecord(int UserId, string Username, string Email, string Role);

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
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL DEFAULT 'user'
            );";
        command.ExecuteNonQuery();
    }

    // role defaults to "user"; nothing reachable over HTTP lets a caller grant themselves
    // "admin" — admin accounts are provisioned directly against the repository.
    public UserRecord AddUser(string username, string email, string password, string role = "user")
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

        if (!InputValidator.IsValidRole(role))
        {
            throw new ArgumentException("Invalid role.", nameof(role));
        }

        var passwordHash = PasswordHasher.Hash(password);

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($username, $email, $passwordHash, $role);
            SELECT last_insert_rowid();";
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$passwordHash", passwordHash);
        command.Parameters.AddWithValue("$role", role);

        try
        {
            var newId = (long)command.ExecuteScalar()!;
            return new UserRecord((int)newId, username, email, role);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT
        {
            throw new DuplicateUserException($"Username '{username}' or email '{email}' already exists.");
        }
    }

    // Parameterized credential lookup: the username placeholder prevents SQL injection,
    // and the password is never compared or stored in plaintext (see PasswordHasher).
    public UserRecord? AuthenticateUser(string username, string password)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Email, PasswordHash, Role FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var userId = reader.GetInt32(0);
        var email = reader.GetString(1);
        var passwordHash = reader.GetString(2);
        var role = reader.GetString(3);

        return PasswordHasher.Verify(password, passwordHash) ? new UserRecord(userId, username, email, role) : null;
    }

    public bool VerifyLogin(string username, string password) => AuthenticateUser(username, password) is not null;

    // Parameterized LIKE search: the search term is bound as a parameter, so wildcard/
    // injection characters in user input are treated as literal text, not query syntax.
    public List<UserRecord> SearchUsersByUsername(string searchTerm)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email, Role FROM Users WHERE Username LIKE $pattern ESCAPE '\\';";
        var escaped = searchTerm.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
        command.Parameters.AddWithValue("$pattern", $"%{escaped}%");

        using var reader = command.ExecuteReader();
        var results = new List<UserRecord>();
        while (reader.Read())
        {
            results.Add(new UserRecord(reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }

        return results;
    }

    public UserRecord? GetUserByUsername(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email, Role FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (reader.Read())
        {
            return new UserRecord(reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3));
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
