using System.Collections.Generic;

namespace Pustok.ViewModels
{
    public class BasketViewModel
    {
        public List<BasketItemViewModel> Items { get; set; } = new List<BasketItemViewModel>();
        public decimal Total { get; set; }  
    }
}
