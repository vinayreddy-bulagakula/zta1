using MySql.Data.MySqlClient;
using ZTAWebApp.Models;
using BCrypt.Net;

namespace ZTAWebApp.Services
{
    public class UserService
{
private string GetConnectionString()
{
    return "server=localhost;port=3307;database=zta_security;user=root;password=root123";
}


    public User GetUserByUsername(string username)
    {
        using (var conn = new MySqlConnection(GetConnectionString()))
        {
            conn.Open();
            string query = "SELECT user_id, username, password_hash, mfa_secret, email, is_active, first_login FROM users WHERE username = @username";
            using (var cmd = new MySqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@username", username);
                using (var reader = cmd.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        return new User
                        {
                            UserId = Convert.ToInt32(reader["user_id"]),
                            Username = reader["username"].ToString(),
                            PasswordHash = reader["password_hash"].ToString(),
                            MFASecret = reader["mfa_secret"].ToString(),
                            Email = reader["email"].ToString()
                        };
                    }
                }
            }
        }
        return null;
    }

    public List<User> GetAllUsers()
    {
        var users = new List<User>();
        using (var conn = new MySqlConnection(GetConnectionString()))
        {
            conn.Open();
            string query = "SELECT user_id, username, email, is_active, first_login, created_at FROM users";
            using (var cmd = new MySqlCommand(query, conn))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    users.Add(new User
                    {
                        UserId = Convert.ToInt32(reader["user_id"]),
                        Username = reader["username"].ToString(),
                        Email = reader["email"].ToString()
                    });
                }
            }
        }
        return users;
    }

    public List<string> GetUserRoles(string username)
    {
        var roles = new List<string>();
        using (var conn = new MySqlConnection(GetConnectionString()))
        {
            conn.Open();
            string query = @"
                SELECT r.role_name
                FROM users u
                JOIN user_roles ur ON u.user_id = ur.user_id
                JOIN roles r ON ur.role_id = r.role_id
                WHERE u.username = @username";
            
            using (var cmd = new MySqlCommand(query, conn))
            {
                cmd.Parameters.AddWithValue("@username", username);
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        roles.Add(reader["role_name"].ToString());
                    }
                }
            }
        }
        return roles;
    }

    public bool AssignRole(string username, string roleName)
    {
        try
        {
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                
                string query = @"
                    INSERT INTO user_roles (user_id, role_id) 
                    SELECT u.user_id, r.role_id 
                    FROM users u, roles r 
                    WHERE u.username = @username AND r.role_name = @roleName";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@username", username);
                    cmd.Parameters.AddWithValue("@roleName", roleName);
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }
        catch
        {
            return false;
        }
    }

    public bool ToggleUserStatus(int userId, bool activate)
    {
        try
        {
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                string query = "UPDATE users SET is_active = @status WHERE user_id = @userId";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@status", activate);
                    cmd.Parameters.AddWithValue("@userId", userId);
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }
        catch
        {
            return false;
        }
    }

    public bool ResetUserMFA(int userId)
    {
        try
        {
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                string query = "UPDATE users SET first_login = 1 WHERE user_id = @userId";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@userId", userId);
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }
        catch
        {
            return false;
        }
    }

    public void LogAdminAction(string adminUsername, string actionType, string targetUserId, string description)
    {
        try
        {
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                string query = @"
                    INSERT INTO admin_actions (admin_user_id, action_type, target_user_id, description) 
                    SELECT u.user_id, @actionType, @targetUserId, @description 
                    FROM users u WHERE u.username = @adminUsername";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@adminUsername", adminUsername);
                    cmd.Parameters.AddWithValue("@actionType", actionType);
                    cmd.Parameters.AddWithValue("@targetUserId", targetUserId);
                    cmd.Parameters.AddWithValue("@description", description);
                    cmd.ExecuteNonQuery();
                }
            }
        }
        catch { }
    }

    public List<SecurityEvent> GetSecurityEvents()
    {
        var events = new List<SecurityEvent>();
        using (var conn = new MySqlConnection(GetConnectionString()))
        {
            conn.Open();
            string query = @"
                SELECT se.event_id, se.event_type, se.severity, se.description, 
                       se.source_ip, se.timestamp, u.username
                FROM security_events se
                LEFT JOIN users u ON se.user_id = u.user_id
                ORDER BY se.timestamp DESC
                LIMIT 100";
            
            using (var cmd = new MySqlCommand(query, conn))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    events.Add(new SecurityEvent
                    {
                        EventId = Convert.ToInt32(reader["event_id"]),
                        EventType = reader["event_type"].ToString(),
                        Severity = reader["severity"].ToString(),
                        Description = reader["description"].ToString(),
                        SourceIp = reader["source_ip"]?.ToString() ?? "",
                        Timestamp = Convert.ToDateTime(reader["timestamp"]),
                        Username = reader["username"]?.ToString() ?? "Unknown"
                    });
                }
            }
        }
        return events;
    }

    public bool ChangePassword(string username, string currentPassword, string newPassword)
    {
        try
        {
            var user = GetUserByUsername(username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(currentPassword, user.PasswordHash))
            {
                return false;
            }

            var hashedNewPassword = BCrypt.Net.BCrypt.HashPassword(newPassword);
            
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                string query = "UPDATE users SET password_hash = @password WHERE username = @username";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@password", hashedNewPassword);
                    cmd.Parameters.AddWithValue("@username", username);
                    return cmd.ExecuteNonQuery() > 0;
                }
            }
        }
        catch
        {
            return false;
        }
    }

    public void LogSecurityEvent(string eventType, string severity, string description, string sourceIp, string username = null)
    {
        try
        {
            using (var conn = new MySqlConnection(GetConnectionString()))
            {
                conn.Open();
                string query = @"
                    INSERT INTO security_events (event_type, severity, description, source_ip, user_id) 
                    SELECT @eventType, @severity, @description, @sourceIp, u.user_id 
                    FROM users u WHERE u.username = @username
                    UNION SELECT @eventType, @severity, @description, @sourceIp, NULL WHERE @username IS NULL";
                
                using (var cmd = new MySqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@eventType", eventType);
                    cmd.Parameters.AddWithValue("@severity", severity);
                    cmd.Parameters.AddWithValue("@description", description);
                    cmd.Parameters.AddWithValue("@sourceIp", sourceIp ?? "");
                    cmd.Parameters.AddWithValue("@username", username ?? (object)DBNull.Value);
                    cmd.ExecuteNonQuery();
                }
            }
        }
        catch { }
    }
}

}
