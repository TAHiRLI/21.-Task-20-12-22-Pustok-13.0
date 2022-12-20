using Pustok.Models;
using System.Collections.Generic;

namespace Pustok.ViewModels
{
	public class CheckoutViewModel
	{
		public Order Order { get; set; }
		public decimal Total { get; set; }	
		public List<CheckoutItemViewModel> BasketItems { get; set; } = new List<CheckoutItemViewModel>();

	}
}
