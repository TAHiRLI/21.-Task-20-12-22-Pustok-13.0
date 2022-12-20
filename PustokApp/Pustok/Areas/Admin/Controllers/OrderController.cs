using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Pustok.Areas.Admin.ViewModels;
using Pustok.DAL;
using Pustok.Enums;
using Pustok.Models;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Pustok.Areas.Admin.Controllers
{
    [Authorize(Roles = "SuperAdmin, Admin, Editor")]
    [Area("Admin")]

    public class OrderController : Controller
    {
        private readonly PustokDbContext _context;

        public OrderController(PustokDbContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page = 1)
        {
            var query = _context.Orders
            .Include(x => x.OrderItems).ThenInclude(x => x.Book)
            .Include(x => x.AppUser);

            var model = PaginatedList<Order>.Create(query, page, 10);

            return View(model);
        }
        public IActionResult Edit(int id)
        {
            var model = _context.Orders.FirstOrDefault(x => x.Id == id);
            return View(model);
        }
        [HttpPost]
        public IActionResult Accept(int id)
        {
            var order = _context.Orders.FirstOrDefault(x => x.Id == id);    
            if(order == null) return NotFound();

            order.OrderStatus = OrderStatus.Accepted;
            _context.SaveChanges();

            return RedirectToAction("index");
        }
        [HttpPost]
        public IActionResult Reject(int id)
        {
            var order = _context.Orders.FirstOrDefault(x => x.Id == id);
            if (order == null) return NotFound();

            order.OrderStatus = OrderStatus.Rejected;
            _context.SaveChanges();

            return RedirectToAction("index");
        }
    }
}
