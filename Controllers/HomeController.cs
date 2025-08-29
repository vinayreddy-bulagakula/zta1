using Microsoft.AspNetCore.Mvc;
using ZTAWebApp.Services;

namespace ZTAWebApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserService _userService;

        public HomeController(UserService userService)
        {
            _userService = userService;
        }
        public IActionResult Dashboard()
        {
            var username = HttpContext.Session.GetString("Username");
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Login", "Auth");
            }

            var roles = _userService.GetUserRoles(username);
            ViewBag.User = username;
            ViewBag.Roles = roles;
            
            if (roles.Contains("admin"))
            {
                ViewBag.UserType = "admin";
            }
            else if (roles.Contains("user"))
            {
                ViewBag.UserType = "user";
            }
            else if (roles.Contains("guest"))
            {
                ViewBag.UserType = "guest";
            }
            else
            {
                ViewBag.UserType = "unknown";
            }

            return View();
        }

        [HttpGet]
        public IActionResult ChangePassword()
        {
            var username = HttpContext.Session.GetString("Username");
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Login", "Auth");
            }

            var roles = _userService.GetUserRoles(username);
            if (roles.Contains("guest"))
            {
                return RedirectToAction("Dashboard");
            }

            return View();
        }

        [HttpPost]
        public IActionResult ChangePassword(ZTAWebApp.Models.ChangePasswordViewModel model)
        {
            var username = HttpContext.Session.GetString("Username");
            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Login", "Auth");
            }

            var roles = _userService.GetUserRoles(username);
            if (roles.Contains("guest"))
            {
                return RedirectToAction("Dashboard");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var success = _userService.ChangePassword(username, model.CurrentPassword, model.NewPassword);
            if (success)
            {
                ViewBag.Success = "Password changed successfully!";
                _userService.LogSecurityEvent("PASSWORD_CHANGE", "NORMAL", $"User {username} changed password", Request.HttpContext.Connection.RemoteIpAddress?.ToString(), username);
            }
            else
            {
                ViewBag.Error = "Current password is incorrect or operation failed";
            }

            return View();
        }
    }
}
