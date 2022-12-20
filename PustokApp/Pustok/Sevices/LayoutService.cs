using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pustok.DAL;
using Pustok.Models;
using Pustok.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;

namespace Pustok.Sevices
{
    public class LayoutService
    {
        private readonly PustokDbContext _context;
        private readonly IHttpContextAccessor _httpAccessor;

        public LayoutService(PustokDbContext context,IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpAccessor = httpContextAccessor;
        }
        public Dictionary<string, string> GetSettings()
        {
            return _context.Settings.ToDictionary(x=> x.Key, x=> x.Value);
        }
        public List<Genre> GetGenres()
        {
            return _context.Genres.ToList();
        }
        public BasketViewModel GetBasket()
        {
            BasketViewModel basketVm = new BasketViewModel();

            if (_httpAccessor.HttpContext.User.Identity.IsAuthenticated && _httpAccessor.HttpContext.User.IsInRole("Member"))
            {
                // user logged in
                var userId = _httpAccessor.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
                var basketItems = _context.BasketItems
                    .Include(x=> x.Book)
                    .ThenInclude(x=> x.BookImages)
                    .Where(x=> x.AppUserId == userId).ToList();


                foreach (var item in basketItems)
                {
                    BasketItemViewModel basketItemVm = new BasketItemViewModel
                    {
                        Id = item.Id,
                        Book = item.Book,
                        Count = item.Count,
                    };
                    basketVm.Items.Add(basketItemVm);
                    basketVm.Total += item.Count * (item.Book.SalePrice * (100 - item.Book.DiscountPercent)/ 100);
                }
            }
            else
            {
                // user not logged in
                List<BasketCookieViewModel> basketList = new List<BasketCookieViewModel>();

                var basketStr = _httpAccessor.HttpContext.Request.Cookies["basket"];
                if (basketStr != null)
                    basketList = JsonConvert.DeserializeObject<List<BasketCookieViewModel>>(basketStr);
                //else
                //{
                //    _httpAccessor.HttpContext.Response.Cookies.Append("basketim", JsonConvert.SerializeObject(basketList));
                //}
                foreach (var item in basketList)
                {

                    Book book = _context.Books.Include(x=> x.BookImages).FirstOrDefault(x => x.Id == item.BookId);

                    BasketItemViewModel basketItemVm = new BasketItemViewModel
                    {
                        Book = book,
                        Count = item.Count,
                    };
                    basketVm.Items.Add(basketItemVm);
                    basketVm.Total += item.Count * (book.SalePrice * (100 - book.DiscountPercent)/ 100);
                }


            }
           return basketVm;
        }
    }
}
