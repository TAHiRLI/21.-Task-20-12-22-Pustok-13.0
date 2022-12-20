using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pustok.Areas.Admin.ViewModels;
using Pustok.DAL;
using Pustok.Models;
using System.Linq;

namespace Pustok.Areas.Admin.Controllers
{
    [Area("Admin")]
    [Authorize(Roles = "SuperAdmin, Admin, Editor")]


    public class TagController : Controller
    {
        private readonly PustokDbContext _context;

        public TagController(PustokDbContext context)
        {
           _context = context;
        }
        public IActionResult Index(int page=1)
        {
            var query = _context.Tags.Include(x=> x.BookTags);
            var tags = PaginatedList<Tag>.Create(query, page, 3);
            return View(tags);
        }
    }
}
