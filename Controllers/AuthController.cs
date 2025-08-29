using Microsoft.AspNetCore.Mvc;
using ZTAWebApp.Models;
using ZTAWebApp.Services;
using Microsoft.AspNetCore.Http;
using OtpNet;
using QRCoder;
using System.Drawing;


namespace ZTAWebApp.Controllers
{
    public class AuthController : Controller
    {
        private readonly UserService _userService;

        public AuthController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(LoginView model)
        {
            var sourceIp = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
            
            var user = _userService.GetUserByUsername(model.Username);
            if (user == null)
            {
                _userService.LogSecurityEvent("LOGIN_ATTEMPT", "MALICIOUS", $"Login attempt for non-existent user: {model.Username}", sourceIp);
                ModelState.AddModelError(string.Empty, "Invalid login details");
                return View();
            }

            if (!BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                _userService.LogSecurityEvent("LOGIN_FAILED", "MALICIOUS", $"Failed password attempt for user: {model.Username}", sourceIp, model.Username);
                ViewBag.Message = "Invalid password.";
                return View();
            }

            var totp = new OtpNet.Totp(Base32Encoding.ToBytes(user.MFASecret));
            if (!totp.VerifyTotp(model.OTP, out long _))
            {
                _userService.LogSecurityEvent("MFA_FAILED", "MALICIOUS", $"Failed MFA attempt for user: {model.Username}", sourceIp, model.Username);
                ViewBag.Message = "Invalid OTP.";
                return View();
            }

            _userService.LogSecurityEvent("LOGIN_SUCCESS", "NORMAL", $"Successful login for user: {model.Username}", sourceIp, model.Username);
            HttpContext.Session.SetString("Username", user.Username);
            return RedirectToAction("Dashboard", "Home");
        }

        public IActionResult Logout()
        {
            var username = HttpContext.Session.GetString("Username");
            if (!string.IsNullOrEmpty(username))
            {
                var sourceIp = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
                _userService.LogSecurityEvent("LOGOUT", "NORMAL", $"User logged out: {username}", sourceIp, username);
            }
            
            HttpContext.Session.Clear();
            return RedirectToAction("Login");
        }

    }
}
