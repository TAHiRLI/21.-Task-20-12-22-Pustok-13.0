using Pustok.Models;
using System.Collections.Generic;

namespace Pustok.ViewModels
{
    public class ProfileViewModel
    {
        public MemberEditViewModel MemberEditViewModel { get; set; }
        public List<Order> Orders { get; set; } = new List<Order>(); 
    }
}
