using Microsoft.AspNetCore.Mvc;
using Microsoft.DotNet.Scaffolding.Shared.Project;
using Microsoft.EntityFrameworkCore;
using Pustok.DAL;
using Pustok.Models;
using Pustok.ViewModels;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Pustok.Controllers
{
    public class ShopController : Controller
    {
        private readonly PustokDbContext _context;
        public ShopController(PustokDbContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page=1, int? genreId=null,List<int> authorIds= null, List<int> tagIds = null, decimal? minPrice=null, decimal? maxPrice=null, string sort="AZ")
        {
         
            ShopViewModel ShopVm = new ShopViewModel();
            var query = _context.Books
                .Include(x => x.BookImages)
                .Include(x => x.Genre).AsQueryable();

            if (genreId != null)
                query = query.Where(x => x.GenreId == genreId);
            if (authorIds != null && authorIds.Count > 0)
                query = query.Where(x => authorIds.Contains(x.AuthorId));
            if(minPrice != null && minPrice != null)
                query = query.Where(x => x.SalePrice >= minPrice && x.SalePrice <= maxPrice);

            switch (sort)
            {
                case "ZA":
                    query = query.OrderByDescending(x => x.Name);
                    break;
                case "lowToHigh":
                    query=query.OrderBy(x => x.SalePrice);
                    break;
                case "highToLow":
                    query = query.OrderByDescending(x => x.SalePrice);
                    break;
                default:
                    query = query.OrderBy(x => x.Name);
                    break;
            }

            ShopVm.Books = PaginatedList<Book>.Create(query, page, 4);
            ShopVm.Authors = _context.Authors.Include(x=> x.Books).ToList();
            ShopVm.Genres = _context.Genres.Include(x=> x.Books).Where(x=> x.Books.Count>0).ToList();   
            ShopVm.Tags = _context.Tags.ToList();
            ShopVm.MinPrice = _context.Books.Min(x => x.SalePrice);
            ShopVm.MaxPrice = _context.Books.Max(x => x.SalePrice);


            ViewBag.selectedAuthor = authorIds;
            ViewBag.selectedGenre = genreId;
            ViewBag.selectedMinPrice = minPrice ?? ShopVm.MinPrice;
            ViewBag.selectedMaxPrice = maxPrice ?? ShopVm.MaxPrice;

            return View(ShopVm);
        }
    }
}
