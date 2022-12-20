using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using NuGet.Common;
using Pustok.DAL;
using Pustok.Enums;
using Pustok.Models;
using Pustok.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Pustok.Controllers
{
    public class OrderController : BaseController
    {
        private readonly PustokDbContext _context;
        private readonly UserManager<AppUser> _userManager;

        public OrderController(PustokDbContext context, UserManager<AppUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }
        public IActionResult Details(int id)
        {
            var model = _context.Orders
                            .Include(x => x.OrderItems)
                            .ThenInclude(x => x.Book).ThenInclude(x => x.Genre)
                            .Include(x => x.OrderItems)
                            .ThenInclude(x => x.Book).ThenInclude(x=> x.Author)
                              .Include(x => x.OrderItems)
                            .ThenInclude(x => x.Book).ThenInclude(x => x.BookImages)
                            .FirstOrDefault(x => x.Id == id);
                            
                        
            return View(model);
        }
        [Authorize(Roles ="Member")]
        public IActionResult Cancel(int id)
        {
            var order = _context.Orders.FirstOrDefault(x => x.Id == id);
            if (order == null)
                return NotFound();

            if (order.OrderStatus == OrderStatus.Pending)
                order.OrderStatus = OrderStatus.Cancelled;
            else
            {
                // bir mesaj verilmelidi 
                return RedirectToAction("details", new { id = id });
            }
            _context.SaveChanges();
            return RedirectToAction("Profile", "account");
        }
        public async Task<IActionResult> Checkout()
        {
            CheckoutViewModel model = await _getCheckoutVM();
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Checkout(Order order)
        {
            if (!ModelState.IsValid)
            {
                CheckoutViewModel model = await _getCheckoutVM();
                model.Order = order;

                return View(model);
            }

            List<BasketItem> basketItems = new List<BasketItem>();

            if (User.Identity.IsAuthenticated)
            {
                basketItems = _context.BasketItems.Include(x => x.Book).Where(x => x.AppUserId == UserId).ToList();
                order.AppUserId = UserId;
                _context.BasketItems.RemoveRange(basketItems);

            }
            else
            {
                Response.Cookies.Delete("basket");
                basketItems = _mapBasketItems(_getCookieBasket());
            }
            // map orders order Items

            order.OrderItems = basketItems.Select(x => new OrderItem
            {
                Name = x.Book.Name,
                BookId = x.BookId,
                Count = x.Count,
                ItemCostPrice = x.Book.CostPrice,
                ItemSalePrice = x.Book.SalePrice,
                ItemDiscountPercent = x.Book.DiscountPercent


            }).ToList();

            order.CreatedAt = DateTime.UtcNow.AddHours(4);
            order.ModifiedAt = DateTime.UtcNow.AddHours(4);


            _context.Orders.Add(order);
            _context.SaveChanges();

            return RedirectToAction("index", "Home");
        }

        private async Task<CheckoutViewModel> _getCheckoutVM()
        {
            CheckoutViewModel model = new CheckoutViewModel();
            List<BasketItem> BasketList = new List<BasketItem>();
            if (User.Identity.IsAuthenticated)
            {
                var user = await _userManager.FindByIdAsync(UserId);

                model.Order = new Order
                {
                    Fullname = user.Fullname,
                    Email = user.Email
                };

                BasketList = _context.BasketItems.Include(x => x.Book).Where(x => x.AppUserId == UserId).ToList();

            }
            else
            {
                List<BasketCookieViewModel> cookieBasket = _getCookieBasket();
                BasketList = _mapBasketItems(cookieBasket);
            }

            model.BasketItems = BasketList.Select(x => new CheckoutItemViewModel
            {
                Count = x.Count,
                Name = x.Book.Name,
                TotalPrice = x.Count * (x.Book.SalePrice * (100 - x.Book.DiscountPercent) / 100)

            }).ToList();
            model.Total = model.BasketItems.Sum(x => x.TotalPrice);

            return model;
        }
        private List<BasketCookieViewModel> _getCookieBasket()
        {
            var basketStr = Request.Cookies["basket"];
            var basketList = new List<BasketCookieViewModel>();

            if (basketStr != null)
                basketList = JsonConvert.DeserializeObject<List<BasketCookieViewModel>>(basketStr);

            return basketList;
        }
        private List<BasketItem> _mapBasketItems(List<BasketCookieViewModel> cookieItems)
        {
            List<BasketItem> basketItems = new List<BasketItem>();

            foreach (var item in cookieItems)
            {
                Book book = _context.Books.FirstOrDefault(x => x.Id == item.BookId);
                if (book == null) continue;

                BasketItem newItem = new BasketItem
                {
                    Book = book,
                    Count = item.Count,
                    BookId = item.BookId,
                };

                basketItems.Add(newItem);

            }

            return basketItems;
        }
    }
}
