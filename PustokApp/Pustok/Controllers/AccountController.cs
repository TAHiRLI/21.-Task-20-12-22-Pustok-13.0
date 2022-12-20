using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using Microsoft.EntityFrameworkCore;
using MimeKit.Text;
using MimeKit;
using Newtonsoft.Json;
using NuGet.Protocol;
using Pustok.DAL;
using Pustok.Models;
using Pustok.ViewModels;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using MailKit.Security;
using MailKit.Net.Smtp;
using Microsoft.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace Pustok.Controllers
{
    public class AccountController : BaseController
    {
        private readonly PustokDbContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;

        public AccountController(PustokDbContext context, UserManager<AppUser> userManager, SignInManager<AppUser> signInManager)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
        }
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Register(MemberRegisterViewModel memberVm)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }


            if (await _userManager.FindByNameAsync(memberVm.Username) != null)
            {
                ModelState.AddModelError("Username", "User already exists");
                return RedirectToAction("Login");
            }
            if (await _userManager.FindByEmailAsync(memberVm.Email) != null)
            {
                ModelState.AddModelError("Email", "Email already exists");
            }


            AppUser appUser = new AppUser
            {
                Email = memberVm.Email,
                Fullname = memberVm.Fullname,
                UserName = memberVm.Username
            };

            var result = await _userManager.CreateAsync(appUser, memberVm.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View();
            }

            await _userManager.AddToRoleAsync(appUser, "Member");



            return RedirectToAction("Login", "Account");
        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(MemberLoginViewModel memberLoginVm, string returnUrl)
        {

            if (!ModelState.IsValid)
            {
                return View();
            }

            AppUser appUser = await _userManager.FindByNameAsync(memberLoginVm.Username);
            if (appUser == null)
            {
                ModelState.AddModelError("", "Username or Password is incorrect !");
                return View();
            }



            var roles = await _userManager.GetRolesAsync(appUser);
            if (!roles.Contains("Member"))
            {
                ModelState.AddModelError("", "Username or Password is incorrect !");
                return View();
            }





            var result = await _signInManager.PasswordSignInAsync(appUser, memberLoginVm.Password, memberLoginVm.IsPersistent, true);

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Too many attempts, please wait 5 minutes");
                return View();
            }

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username or Password is incorrect !");
                return View();
            }
            if (returnUrl != null)
                return Redirect(returnUrl);
            // get basket cookies
            var basketStr = HttpContext.Request.Cookies["basket"];
            if (basketStr != null)
            {
                var basketList = JsonConvert.DeserializeObject<List<BasketCookieViewModel>>(basketStr);

                foreach (var item in basketList)
                {
                    BasketItem basketItem = _context.BasketItems.FirstOrDefault(x => x.AppUserId == appUser.Id && x.BookId == item.BookId);

                    if (basketItem == null)
                    {
                        basketItem = new BasketItem
                        {

                            BookId = item.BookId,
                            Count = item.Count,
                            CreatedTime = DateTime.UtcNow.AddHours(4)

                        };
                        appUser.BasketItems.Add(basketItem);

                    }
                    else
                    {
                        basketItem.Count += item.Count;
                    }


                }
            }

            _context.SaveChanges();

            return RedirectToAction("Index", "Home");
        }

        //public IActionResult Show()
        //{
        //    if (User.Identity.IsAuthenticated)
        //    {
        //        return Content(User.Identity.Name);
        //    }
        //    return Content("User Is logged Out");
        //}
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> Profile()
        {
            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);
            if (appUser == null) return NotFound();

            ProfileViewModel ProfileVm = new ProfileViewModel();

            MemberEditViewModel memberEditVm = new MemberEditViewModel();
            memberEditVm.Fullname = appUser.Fullname;
            memberEditVm.UserName = appUser.UserName;
            memberEditVm.Email = appUser.Email;


            ProfileVm.MemberEditViewModel = memberEditVm;
            ProfileVm.Orders = _getOrders();


            return View(ProfileVm);
        }
        [HttpPost]
        [Authorize(Roles = "Member")]
        public async Task<IActionResult> Profile(MemberEditViewModel memberEditVm)
        {
            AppUser appUser = await _userManager.FindByNameAsync(User.Identity.Name);
            if (appUser == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction("login");
            }
            ProfileViewModel ProfileVm = new ProfileViewModel();
            ProfileVm.MemberEditViewModel = memberEditVm;
            ProfileVm.Orders = _getOrders();


            if (memberEditVm.Fullname != appUser.Fullname)
                appUser.Fullname = memberEditVm.Fullname;

            if (memberEditVm.Email != appUser.Email && _context.AppUsers.Any(x => x.Email == memberEditVm.Email))
                ModelState.AddModelError("Email", "This email already exists");

            if (memberEditVm.UserName != appUser.UserName && _context.AppUsers.Any(x => x.UserName == memberEditVm.UserName))
                ModelState.AddModelError("Username", "This Username already exists");

            if (!ModelState.IsValid)
            {

                return View(ProfileVm);
            }

            var isUpdated = new IdentityResult();
            if (memberEditVm.CurrentPassword != null || memberEditVm.NewPassword != null)
            {


                if (memberEditVm.CurrentPassword != null)
                {
                    isUpdated = await _userManager.ChangePasswordAsync(appUser, memberEditVm.CurrentPassword, memberEditVm.NewPassword);
                    if (!isUpdated.Succeeded)
                    {
                        foreach (var error in isUpdated.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        return View(ProfileVm);
                    }
                }


            }

            appUser.Email = memberEditVm.Email;
            appUser.UserName = memberEditVm.UserName;
            appUser.Fullname = memberEditVm.Fullname;

            var result = await _userManager.UpdateAsync(appUser);


            _context.SaveChanges();



            await _signInManager.SignInAsync(appUser, true);

            return RedirectToAction("index", "home");
        }
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "home");
        }

        private List<Order> _getOrders()
        {
            List<Order> orders = _context.Orders
                    .Include(x => x.AppUser)
                    .Include(x => x.OrderItems)
                    .ThenInclude(x => x.Book)
                    .Where(x => x.AppUserId == UserId).ToList();

            return orders;
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVeiwModel forgotVm)
        {
            if (!ModelState.IsValid)
                return View();

            AppUser user = await _userManager.FindByEmailAsync(forgotVm.Email);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid Email Address !!!");
                return View();
            }
            //create token to verify
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // create url to send
            var url = Url.Action("verifypasswordreset", "account", new { email = user.Email, token = token }, Request.Scheme);


            // create Email
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse("wilhelm.bins72@ethereal.email"));
            email.To.Add(MailboxAddress.Parse("wilhelm.bins72@ethereal.email"));
            email.Subject = "Test Email Subject";
            email.Body = new TextPart(TextFormat.Html) { Text = $"<h1>To Reset your password click <a href=\"{url}\">Here</a></h1>" };

            // send email
            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, SecureSocketOptions.StartTls);
            smtp.Authenticate("wilhelm.bins72@ethereal.email", "kbu41wuYkSP1Vf6hJv");
            smtp.Send(email);
            smtp.Disconnect(true);

            TempData["success"] = "Email successuly sent";
            return View();
        }
        public async Task<IActionResult> VerifyPasswordReset(string email, string token)
        {

            AppUser user = await _userManager.FindByEmailAsync(email);

            if (user == null || !await _userManager.VerifyUserTokenAsync(user, _userManager.Options.Tokens.PasswordResetTokenProvider, "ResetPassword", token))
            {
                return NotFound();
            }

            TempData["email"] = email;
            TempData["token"] = token;

            return RedirectToAction("resetPassword");
        }

        public IActionResult ResetPassword()
        {
            var email = TempData["email"];
            var token = TempData["token"];


            return View();
        }
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel resetVm)
        {
            if (!ModelState.IsValid)
            {
                return RedirectToAction("resetPassword");
            }
            

            var user = await _userManager.FindByEmailAsync(resetVm.Email);
            if (user == null) return NotFound();



           var result = await _userManager.ResetPasswordAsync(user,resetVm.Token, resetVm.Password);

            if(!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View();
            }

            return RedirectToAction("login");
        }



    }


}
