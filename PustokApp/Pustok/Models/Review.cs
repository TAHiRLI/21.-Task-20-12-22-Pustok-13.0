using System;
using System.ComponentModel.DataAnnotations;

namespace Pustok.Models
{
    public class Review:BaseEntity
    {
        public int BookId { get; set; }
        public string AppUserId { get; set; }
        [MaxLength(200)]
        public string Text { get; set; }
        [Range(1,5)]
        public byte Rate { get; set; }

        public Book Book { get; set; }

        public AppUser AppUser { get; set; }
    }
}
