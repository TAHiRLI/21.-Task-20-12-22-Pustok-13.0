using Microsoft.Build.Framework;
using System.ComponentModel.DataAnnotations;
using RequiredAttribute = System.ComponentModel.DataAnnotations.RequiredAttribute;

namespace Pustok.ViewModels
{
    public class MemberLoginViewModel
    {
        [Required]
        [MaxLength(25)]
        public string Username { get; set; }
        [DataType(DataType.Password)]
        [Required]
        [MaxLength(20)]
        public string Password { get; set; }
        public bool IsPersistent { get; set; }
    }
}
