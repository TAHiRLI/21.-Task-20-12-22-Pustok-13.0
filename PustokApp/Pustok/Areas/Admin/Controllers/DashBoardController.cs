using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace Pustok.Areas.manage.Controllers
{

    [Area("Admin")]
    [Authorize(Roles = "SuperAdmin, Admin, Editor")]
    public class DashBoardController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        public IActionResult Error()
        {
            return View();
        }
    }
}
