using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels
{
	public class MemberEditViewModel
	{
        [Required]
		[MaxLength(25)]
		public string Fullname { get; set; }
        [Required]
        [MaxLength(25)]
        public string UserName { get; set; }
        [Required]
        [MaxLength(100)]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
        [MaxLength(20)]
        public string CurrentPassword { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]

        public string NewPassword { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
		[Compare("NewPassword", ErrorMessage = "Paswords do not match")]
		public string ConfirmPassword { get; set; }


	}
}
