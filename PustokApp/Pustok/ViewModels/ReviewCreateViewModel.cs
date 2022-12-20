using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels
{
    public class ReviewCreateViewModel
    {
        [Range(1, 5)]
        public byte Rate { get; set; }
        [MaxLength(200)]
        [Required]
        public string Text { get; set; }
        public int BookId { get; set; }
    }
}
