using Pustok.Models;
using System.Collections.Generic;

namespace Pustok.ViewModels
{
    public class BookDetailViewModel
    {
        public ReviewCreateViewModel ReviewCreate { get; set; }
        public Book Book { get; set; }
        public List<Book> RelatedBooks { get; set; } = new List<Book>();
        public List<Review> Reviews { get; set; } = new List<Review>();
    }
}
