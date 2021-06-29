using Sitecore.ExperienceForms.Data;
using System;
using System.Collections.Generic;
using System.Web;
using Microsoft.Extensions.DependencyInjection;
using Sitecore.DependencyInjection;
using Sitecore.ExperienceForms.Data.Entities;
using Sitecore.ExperienceForms.Models;
using Sitecore.ExperienceForms.Mvc;
using Sitecore.ExperienceForms.Mvc.Models.Fields;
using Sitecore.ExperienceForms.Mvc.Models.Validation;
using System.Web.Mvc;
using System.ComponentModel.DataAnnotations;
using System.IO;
using Cloudmersive.APIClient.NET.VirusScan.Client;
using Cloudmersive.APIClient.NET.VirusScan.Api;
using Cloudmersive.APIClient.NET.VirusScan.Model;

namespace VirusValidation
{
    public class VirusValidation : ValidationElement<string>
    {
        private IFormRenderingContext _formRenderingContext;
        private IFileStorageProvider _fileStorageProvider;
        private ValidationDataModel _validationItem;

        public VirusValidation(ValidationDataModel validationItem) : base(validationItem)
        {
            this._validationItem = validationItem;
            this._fileStorageProvider = ServiceLocator.ServiceProvider.GetService<IFileStorageProvider>();
            this._formRenderingContext = ServiceLocator.ServiceProvider.GetService<IFormRenderingContext>(); ;
        }

        public override IEnumerable<ModelClientValidationRule> ClientValidationRules
        {
            get
            {
                var clientValidationRule = new ModelClientValidationRule
                {
                    ErrorMessage = FormatMessage(Title),
                    ValidationType = "regex"
                };

                yield return clientValidationRule;
            }
        }

        public string Title { get; set; }

        public override ValidationResult Validate(object value)
        {
            if (value != null)
            {
                List<HttpPostedFileBase> httpPostedFileBaseList = value as List<HttpPostedFileBase>;
                if (httpPostedFileBaseList != null)
                {

                    List<StoredFileInfo> storedFiledList = new List<StoredFileInfo>();

                    foreach (HttpPostedFileBase httpPostedFileBase in httpPostedFileBaseList)
                    {
                        if (httpPostedFileBase == null)
                        {
                            return new ValidationResult(FormatMessage(Title));
                        }

                        var apikey = Sitecore.Configuration.Settings.GetSetting("CloudmersiveApiKey");
                        if (string.IsNullOrEmpty(apikey))
                        {
                            Logger.Warn("CloudmersiveApiKey is empty");
                        }
                        Configuration.Default.AddApiKey("Apikey", apikey);


                        var file = ReadAllBytes(httpPostedFileBase.InputStream);

                        using (MemoryStream stream = new MemoryStream(file))
                        {
                            var apiInstance = new ScanApi();

                            try
                            {
                                // Scan a file for viruses
                                VirusScanResult result = apiInstance.ScanFile((Stream)stream);
                                if (result.FoundViruses != null && result.FoundViruses.Count > 0)
                                {
                                    return new ValidationResult(FormatMessage(Title));
                                }
                            }
                            catch (Exception e)
                            {
                                Logger.Warn("Form Virusscan Cloudmersive Exception ", e.Message);
                                return new ValidationResult("Error with Virus scanner");
                            }

                            stream.Position = 0;
                            var fileId = this._fileStorageProvider.StoreFile(stream, httpPostedFileBase.FileName);
                            storedFiledList.Add(new StoredFileInfo()
                            {
                                FileId = fileId,
                                FileName = httpPostedFileBase.FileName
                            });
                        }

                    }

                    // Add the stored image to the postedFileList
                    List<IViewModel> postedFieldList = new List<IViewModel>();
                    postedFieldList.Add(new FileUploadViewModel()
                    {
                        AllowSave = false,
                        Name = "Face",
                        ItemId = Guid.NewGuid().ToString(),
                        Value = storedFiledList,
                        Files = httpPostedFileBaseList
                    });
                    _formRenderingContext.StorePostedFields(postedFieldList);
                }
            }
            return ValidationResult.Success;
        }

        public byte[] ReadAllBytes(Stream stream)
        {
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                return ms.ToArray();
            }
        }

        public override void Initialize(object validationModel)
        {
            base.Initialize(validationModel);

            var obj = validationModel as StringInputViewModel;
            if (obj != null)
            {
                Title = obj.Title;
            }
        }


    }
}