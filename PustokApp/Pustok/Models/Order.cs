using Pustok.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Pustok.Models
{
    public class Order:BaseEntity
    {
        public string? AppUserId { get; set; }
        public AppUser? AppUser { get; set; }
        [MaxLength(25)]
        [Required]
        public string Fullname { get; set; }
        [MaxLength(100)]
        [Required]


        public string Email { get; set; }
        [MaxLength(250)]
        [Required]


        public string Address1 { get; set; }
        [MaxLength(250)]


        public string Address2 { get; set; }
        [Required]
        [MaxLength(20)]
        public string City { get; set; }
        [Required]
        [MaxLength(10)]
        public string ZipCode { get; set; }
        [MaxLength(500)]
        public string Note { get; set; }
        public OrderStatus OrderStatus { get; set; } = OrderStatus.Pending;


        public List<OrderItem> OrderItems { get; set; } = new List<OrderItem>();
    }
}
