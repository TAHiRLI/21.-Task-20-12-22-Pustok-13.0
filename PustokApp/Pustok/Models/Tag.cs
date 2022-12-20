using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Pustok.Models
{
    public class Tag
    {
        public int Id { get; set; }
        [MaxLength(25)]
        public string Name { get; set; }

        public List<BookTag> BookTags { get; set; } = new List<BookTag>();

    }
}
