using Microsoft.AspNetCore.Mvc;
using ZTAWebApp.Models;
using ZTAWebApp.Services;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using QRCoder;

namespace ZTAWebApp.Controllers
{
    public class AdminController : Controller
    {
        private readonly UserService _userService;
        private readonly HttpClient _httpClient;

        public AdminController(UserService userService, HttpClient httpClient)
        {
            _userService = userService;
            _httpClient = httpClient;
        }

        private bool IsAdmin()
        {
            var username = HttpContext.Session.GetString("Username");
            if (string.IsNullOrEmpty(username)) return false;
            
            var roles = _userService.GetUserRoles(username);
            return roles.Contains("admin");
        }

        public IActionResult Dashboard()
        {
            if (!IsAdmin())
            {
                return RedirectToAction("Login", "Auth");
            }

            var users = _userService.GetAllUsers();
            return View(users);
        }

        [HttpGet]
        public IActionResult CreateUser()
        {
            if (!IsAdmin())
            {
                return RedirectToAction("Login", "Auth");
            }

            ViewBag.Roles = new List<string> { "admin", "user", "guest" };
            return View();
        }

        [HttpPost]
public async Task<IActionResult> CreateUser(CreateUserViewModel model)
{
    if (!IsAdmin())
    {
        return RedirectToAction("Login", "Auth");
    }

    if (!ModelState.IsValid)
    {
        ViewBag.Roles = new List<string> { "admin", "user", "guest" };
        return View(model);
    }

    try
    {
        // Prepare request for backend API
        var requestData = new
        {
            username = model.Username,
            password = model.Password,
            email = model.Email
        };

        var json = JsonSerializer.Serialize(requestData);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        // Call backend API to register user
        var response = await _httpClient.PostAsync("http://localhost:5001/api/auth/register", content);

        if (response.IsSuccessStatusCode)
        {
            // Parse backend response for MFA secret
            var responseJson = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseJson);
            var mfaSecret = doc.RootElement.GetProperty("mfa_secret").GetString();

            // Assign role
            _userService.AssignRole(model.Username, model.Role);

            // Log admin action
            var adminUsername = HttpContext.Session.GetString("Username");
            _userService.LogAdminAction(adminUsername, "CREATE_USER", model.Username,
                $"Created user {model.Username} with role {model.Role}");

            // Generate inline QR code (Base64) for Google Authenticator
            var uri = $"otpauth://totp/ZTA%20Security%20System:{model.Username}?secret={mfaSecret}&issuer=ZTA%20Security%20System&digits=6&period=30";
            var qrGenerator = new QRCoder.QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(uri, QRCoder.QRCodeGenerator.ECCLevel.Q);
            var qrCode = new QRCoder.PngByteQRCode(qrCodeData);
            var qrBytes = qrCode.GetGraphic(20);

            ViewBag.QRBase64 = "data:image/png;base64," + Convert.ToBase64String(qrBytes);
            ViewBag.Success = true;
        }
        else
        {
            ViewBag.Error = "Failed to create user";
        }
    }
    catch (Exception ex)
    {
        ViewBag.Error = "Error creating user: " + ex.Message;
    }

    ViewBag.Roles = new List<string> { "admin", "user", "guest" };
    return View(model);
}


        [HttpPost]
        public IActionResult ToggleUserStatus(int userId, bool activate)
        {
            if (!IsAdmin())
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var success = _userService.ToggleUserStatus(userId, activate);
            var adminUsername = HttpContext.Session.GetString("Username");
            var action = activate ? "ACTIVATE_USER" : "DEACTIVATE_USER";
            
            _userService.LogAdminAction(adminUsername, action, userId.ToString(), $"User {(activate ? "activated" : "deactivated")}");

            return Json(new { success = success });
        }

        [HttpPost]
        public IActionResult ResetMFA(int userId)
        {
            if (!IsAdmin())
            {
                return Json(new { success = false, message = "Unauthorized" });
            }

            var success = _userService.ResetUserMFA(userId);
            var adminUsername = HttpContext.Session.GetString("Username");
            
            _userService.LogAdminAction(adminUsername, "RESET_MFA", userId.ToString(), "MFA reset for user");

            return Json(new { success = success });
        }

        public IActionResult SIEM()
        {
            if (!IsAdmin())
            {
                return RedirectToAction("Login", "Auth");
            }

            var events = _userService.GetSecurityEvents();
            return View(events);
        }
    }
}