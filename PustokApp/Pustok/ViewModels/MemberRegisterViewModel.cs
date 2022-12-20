using Microsoft.Build.ObjectModelRemoting;
using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels
{
	public class MemberRegisterViewModel
	{
        [Required]
        [MaxLength(25)]
        public string Username { get; set; }
        [Required]
        [MaxLength(25)]
        public string Fullname { get; set; }
		[MaxLength(100)]
        [Required]
        public string Email { get; set; }
		[MaxLength(20)]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
		[MaxLength(20)]
        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match!")]
        public string ConfirmPassword { get; set; }
	}
}
