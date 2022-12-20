using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace Pustok.Models
{
    public class AppUser:IdentityUser
    {
        public string Fullname { get; set; }
        public List<BasketItem> BasketItems { get; set; } = new List<BasketItem>();
    }
}
