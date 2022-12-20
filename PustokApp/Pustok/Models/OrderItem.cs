using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Models
{
    public class OrderItem
    {

        public int Id { get; set; }
        public int? BookId { get; set; }
        [MaxLength(25)]
        public int OrderId { get; set; }
        public string Name { get; set; }
        public int Count { get; set; }

        [Column(TypeName = "money")]
        public decimal ItemCostPrice { get; set; }

        [Column(TypeName = "money")]
        public decimal ItemSalePrice { get; set; }

        [Column(TypeName = "decimal(18,2)")]
        public decimal ItemDiscountPercent { get; set; }

        public Order Order { get; set; }
        public Book? Book { get; set; }
    }
}
