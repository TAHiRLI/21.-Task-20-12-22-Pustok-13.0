using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pustok.DAL;
using Pustok.Migrations;
using Pustok.Models;
using Pustok.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Pustok.Controllers
{
    public class BookController : Controller
    {
        private readonly PustokDbContext _context;
        private readonly UserManager<AppUser> _userManager;

        public BookController(PustokDbContext context, UserManager<AppUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }
        public IActionResult GetBook(int id)
        {
            Book book = _context.Books.Include(x => x.Genre).Include(x => x.BookImages).Include(x => x.Author).Include(X => X.BookTags).ThenInclude(x => x.Tag).FirstOrDefault(x => x.Id == id);
            return PartialView("_BookModalPartial", book);
        }
        public IActionResult Details(int id)
        {
            Book Book = _context.Books
             .Include(x => x.Author)
             .Include(x => x.BookImages)
             .Include(x => x.Genre)
             .Include(x => x.BookTags)
             .ThenInclude(x => x.Tag)
             .FirstOrDefault(x => x.Id == id);

            var RelatedBooks = _context.Books
                .Include(x => x.BookImages)
                .Include(x => x.Author)
                .Include(x => x.Genre)
                .Include(x => x.BookTags).ThenInclude(x => x.Tag)
                .Where(x => x.Genre == Book.Genre || x.AuthorId == Book.AuthorId)
                .ToList();

            BookDetailViewModel bookModel = new BookDetailViewModel
            {
                Book = Book,
                RelatedBooks = RelatedBooks,
                ReviewCreate = new ReviewCreateViewModel { BookId = id },
                Reviews = _context.Reviews.Include(x => x.AppUser).Where(x => x.BookId == id).ToList(),

            };
            return View(bookModel);
        }
        [Authorize(Roles = "Member")]
        [HttpPost]
        public async Task<IActionResult> Review(ReviewCreateViewModel reviewVm)
        {
            // # deactivate if you want to enable a person to add multiple reviews
           if (_context.Reviews.Include(x => x.AppUser).Any(x => x.BookId == reviewVm.BookId && x.AppUser.UserName == User.Identity.Name))
              ModelState.AddModelError("", "You have already reviewed this product");


            Book book = _context.Books
           .Include(x => x.Author)
           .Include(x => x.BookImages)
           .Include(x => x.Genre)
           .Include(x=> x.Reviews).ThenInclude(x=> x.AppUser)
           .Include(x => x.BookTags)
           .ThenInclude(x => x.Tag)
           .FirstOrDefault(x => x.Id == reviewVm.BookId);
            if (book == null)
                return NotFound();

            if (!ModelState.IsValid)
            {

                BookDetailViewModel detailVm = new BookDetailViewModel
                {
                    Book = book,
                    RelatedBooks = _context.Books
                    .Include(x => x.BookImages)
                    .Include(x => x.Author)
                    .Include(x => x.Genre)
                    .Include(x => x.BookTags).ThenInclude(x => x.Tag)
                    .Where(x => x.Genre == book.Genre || x.AuthorId == book.AuthorId)
                    .ToList(),
                    ReviewCreate = reviewVm,
                    Reviews = _context.Reviews.Include(x => x.AppUser).Where(x => x.BookId == book.Id).ToList(),

                };

                return View("details", detailVm);
            }

            Review review = new Review
            {
                AppUser = await _userManager.FindByNameAsync(User.Identity.Name),
              //  BookId = reviewVm.BookId,
                Rate = reviewVm.Rate,
                Text = reviewVm.Text,
                CreatedAt = DateTime.UtcNow.AddHours(4),

            };




            book.Reviews.Add(review);
            book.AvgRate = (byte)Math.Ceiling( book.Reviews.Average(x => x.Rate));
            _context.SaveChanges();


            return RedirectToAction("details", new { id = reviewVm.BookId });
        }

        public async Task<IActionResult> AddToBasket(int bookId, int count = 1)
        {
            AppUser user = null;
            if (User.Identity.IsAuthenticated)
            {
                user = await _userManager.FindByNameAsync(User.Identity.Name);
            }

            if (!_context.Books.Any(x => x.Id == bookId && x.StockStatus == true))
            {
                return NotFound();
            }

            BasketViewModel BasketVm = new BasketViewModel();

            if (user != null)
            {
                BasketItem basketItem = _context.BasketItems.FirstOrDefault(x => x.BookId == bookId && x.AppUserId == user.Id);
                if (basketItem == null)
                {

                    basketItem = new BasketItem
                    {
                        BookId = bookId,
                        AppUserId = user.Id,
                        Count = count,
                        CreatedTime = DateTime.UtcNow.AddHours(4)
                    };

                    _context.BasketItems.Add(basketItem);

                }
                else
                {
                    basketItem.Count = basketItem.Count + count;
                }
                _context.SaveChanges();

                var basketItems = _context.BasketItems
                    .Include(x=> x.Book)
                    .ThenInclude(x=> x.BookImages)
                    .Where(x=> x.AppUserId == user.Id)
                    .ToList();


                foreach (var item in basketItems)
                {
                    BasketItemViewModel BasketItemVm = new BasketItemViewModel
                    {
                        Book = item.Book,
                        Count = item.Count,
                        Id = item.Id
                    };

                    BasketVm.Items.Add(BasketItemVm);
                    BasketVm.Total += item.Count * (item.Book.SalePrice * (100 - item.Book.DiscountPercent) / 100);
                }
            }
            else
            {
                List<BasketCookieViewModel> basketCookieItems = new List<BasketCookieViewModel>();
                var basket = HttpContext.Request.Cookies["basket"];
                if(basket != null)
                    basketCookieItems = JsonConvert.DeserializeObject<List<BasketCookieViewModel>>(basket);

                var basketItem = basketCookieItems.FirstOrDefault(x => x.BookId == bookId);
                if (basketItem != null)
                    basketItem.Count += count;
                else
                {
                    basketItem = new BasketCookieViewModel();
                    basketItem.Count = count;
                    basketItem.BookId = bookId;
                    basketCookieItems.Add(basketItem);
                }

                HttpContext.Response.Cookies.Append("basket", JsonConvert.SerializeObject(basketCookieItems));


                foreach (var item in basketCookieItems)
                {
                    Book book = _context.Books.Include(x=> x.BookImages).FirstOrDefault(x => x.Id == item.BookId);
                    
                    BasketItemViewModel CartItem = new BasketItemViewModel
                    {
                        Book = book,
                        Count = item.Count,


                    };
                    BasketVm.Items.Add(CartItem);
                    BasketVm.Total += item.Count * (CartItem.Book.SalePrice * (100 - CartItem.Book.DiscountPercent) / 100);
                }


                

            }

            return PartialView("_BasketPartial", BasketVm);
        }

        public async Task<IActionResult> DeleteItem(int bookId)
        {
            
            BasketViewModel BasketVm = new BasketViewModel();
            if (User.Identity.IsAuthenticated)
            {
                var  user =await _userManager.FindByNameAsync(User.Identity.Name);
                var existBasketItem =  _context.BasketItems.Where(x=> x.AppUserId == user.Id).FirstOrDefault(x => x.BookId == bookId);
                if (existBasketItem == null)
                    return NotFound();



                _context.BasketItems.Remove(existBasketItem);
                _context.SaveChanges();



                var basketItems = _context.BasketItems
                  .Include(x => x.Book)
                  .ThenInclude(x => x.BookImages)
                  .Where(x => x.AppUserId == user.Id)
                  .ToList();

                foreach (var item in basketItems)
                {
                    BasketItemViewModel basketItemVm = new BasketItemViewModel
                    {
                        Book = item.Book,
                        Count = item.Count
                    };
                    BasketVm.Items.Add(basketItemVm);
                    BasketVm.Total += item.Count * (item.Book.SalePrice * (100 - item.Book.DiscountPercent) / 100);

                }

            }
            else
            {
                var basket =   HttpContext.Request.Cookies["basket"];
                if (basket == null)
                    return NotFound();

                var basketList = JsonConvert.DeserializeObject<List<BasketCookieViewModel>>(basket);
                var basketItem = basketList.FirstOrDefault(x => x.BookId == bookId);
                if (basketItem == null)
                    return NotFound();

                basketList.Remove(basketItem);

                HttpContext.Response.Cookies.Append("basket", JsonConvert.SerializeObject(basketList));

                foreach (var item in basketList)
                {
                    Book book = _context.Books.Include(x=> x.BookImages).FirstOrDefault(x => x.Id == item.BookId);
                    BasketItemViewModel basketItemVm = new BasketItemViewModel
                    {
                        Book = book,
                        Count = item.Count
                    };
                    BasketVm.Items.Add(basketItemVm);
                    BasketVm.Total += item.Count * (book.SalePrice * (100 - book.DiscountPercent) / 100);

                }


            }

            return PartialView("_BasketPartial", BasketVm);
        }
       
    }
}
