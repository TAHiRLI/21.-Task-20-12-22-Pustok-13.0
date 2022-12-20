using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;

namespace Pustok.Attributes.ValidationAttributes
{
    public class AllowedFileTypes:ValidationAttribute
    {
        private string[] _fileTypes;
        public AllowedFileTypes(params string[] fileTypes)
        {
            _fileTypes = fileTypes;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            List<IFormFile> files = new List<IFormFile>();
            if (value is IFormFile)
            {
                var file = value as IFormFile;
                files.Add(file);
            }
            else if (value is List<IFormFile>)
            {
                files = value as List<IFormFile>;
            }

            foreach (var file in files)
            {
                if(file != null)
                {
                    if (!_fileTypes.Contains(file.ContentType))
                        return new ValidationResult("File type must be " + String.Join(", ", _fileTypes));
                }
            }

            return ValidationResult.Success;
        }
    }

}
