using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Pustok.Areas.Admin.ViewModels;
using Pustok.Models;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Pustok.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager,RoleManager<IdentityRole>  roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        //public async Task<IActionResult> CreateRoles()
        //{
        //    IdentityRole identityRole1 = new IdentityRole("Admin");
        //    IdentityRole identityRole2 = new IdentityRole("Member");
        //    IdentityRole identityRole3 = new IdentityRole("SuperAdmin");
        //    IdentityRole identityRole4 = new IdentityRole("Editor");

        //    await _roleManager.CreateAsync(identityRole1);
        //    await _roleManager.CreateAsync(identityRole2);
        //    await _roleManager.CreateAsync(identityRole3);
        //    await _roleManager.CreateAsync(identityRole4);
        //    return Ok();
        //}

        ////=============================================
        //// create admin
        ////=============================================
        //public async Task<IActionResult> CreateAdmin()
        //{
        //    AppUser user = new AppUser
        //    {
        //        Fullname = "Tahir Tahirli",
        //        Email = "TahirTahirli@gmail.com",
        //        UserName = "TahirAdmin"
        //    };

        //    var result = await _userManager.CreateAsync(user, "Admin123");
        //    if (!result.Succeeded)
        //    {
        //        return Content("problem") ;
        //    }
        //    await _userManager.AddToRoleAsync(user, "SuperAdmin");



        //    return Ok();
        //}

        public IActionResult Login()
        {

            return View();

        }

        [HttpPost]
        public async Task<IActionResult> Login(AdminLoginViewModel adminModel,string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }
            var user = await _userManager.FindByNameAsync(adminModel.UserName);
            if(user == null)
            {
                ModelState.AddModelError("","UserName or password is incorrect");
                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(user, adminModel.Password, false, true);
            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Too many attempts, please wait 5 minutes");
                return View();
            }

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "UserName or password is incorrect");
                return View();
            }
            if (returnUrl != null)
                return Redirect(returnUrl);

            return RedirectToAction("Index", "Dashboard");
        }
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }
    }
}
