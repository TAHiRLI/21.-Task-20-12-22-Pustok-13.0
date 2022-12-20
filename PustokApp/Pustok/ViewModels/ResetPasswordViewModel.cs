using System.ComponentModel.DataAnnotations;

namespace Pustok.ViewModels
{
    public class ResetPasswordViewModel
    {
        [MaxLength(20)]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [MaxLength(20)]
        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage ="passwords do not match")]
        public string ConfirmPassword { get; set; }

        public string Email { get; set; }
        public string Token { get; set; }
    }
}
