using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Metadata;
using Pustok.Attributes.ValidationAttributes;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Pustok.Models
{
    public class Book: BaseEntity
    {
        public int GenreId { get; set; }
        [MaxLength(50)]
        public string Name { get; set; }
        [MaxLength(200)]
        public string Description { get; set; }
        public int AuthorId { get; set; }
        public bool StockStatus { get; set; }
        public bool IsSpecial { get; set; }
        public byte AvgRate { get; set; }
        public bool IsNew { get; set; }

        [Column(TypeName ="money")]
        public decimal CostPrice { get; set; }


        [Column(TypeName = "money")]
        public decimal SalePrice { get; set; }

        [Column(TypeName = "decimal(18,2)")]
        public decimal DiscountPercent { get; set; }
        [NotMapped]
        [AllowedFileTypes("image/jpeg","image/png")]
        [MaxFileSizeAttr(2)]
        public IFormFile? PosterImg { get; set; }

        [NotMapped]
        [AllowedFileTypes("image/jpeg", "image/png")]
        [MaxFileSizeAttr(2)]
        public IFormFile? HoverImg { get; set; }
        [NotMapped]
        [MaxFileSizeAttr(2)]
        public List<IFormFile>? ImageFiles { get; set; }

        [NotMapped]
        public List<int> BookImageIds { get; set; } = new List<int>();
        [NotMapped]
        public List<int> TagIds { get; set; } = new List<int>();




        public Genre Genre { get; set; }
        public Author Author { get; set; }


        public List<Review> Reviews { get; set; } = new List<Review>();
        public List<OrderItem> OrderItems { get; set; }
        public List<BookImage> BookImages { get; set; } = new List<BookImage>();
        public List<BookTag> BookTags { get; set; } = new List<BookTag>();
    }
}
