// <copyright file="MainPage.xaml.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>
namespace TestUno
{
    using System;
    using System.Threading.Tasks;
    using Isopoh.Cryptography.Argon2;
    using Isopoh.Cryptography.SecureArray;
    using Windows.UI.Xaml.Controls;

    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage
    {
        private string previousSecret = string.Empty;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainPage"/> class.
        /// </summary>
        public MainPage()
        {
            this.InitializeComponent();
            this.Os.Text = $"Operating System: {SecureArray.DefaultCall.Os}, {IntPtr.Size * 8}-bit";
            this.Secret.LostFocus += (sender, e) => Task.Run(
                async () => await this.CalculateHashAsync());
            this.TimeCost.BeforeTextChanging += this.OnBeforePositiveIntTextChange;
            this.MemoryCost.BeforeTextChanging += this.OnBeforePositiveIntTextChange;
            this.Parallelism.BeforeTextChanging += this.OnBeforePositiveIntTextChange;
            this.HashLength.BeforeTextChanging += this.OnBeforePositiveIntTextChange;
        }

        /// <summary>
        /// Called before a positive integer text change.
        /// </summary>
        /// <param name="o">The object called on.</param>
        /// <param name="arg">The text change event information.</param>
        public void OnBeforePositiveIntTextChange(
            TextBox o,
            TextBoxBeforeTextChangingEventArgs arg)
        {
            arg.Cancel = !int.TryParse(arg.NewText, out int val) || val < 1;
        }

        /// <summary>
        /// Called to calculate the hash with the parameters from the form.
        /// </summary>
        /// <returns>Task that calculates the hash.</returns>
        public async Task CalculateHashAsync()
        {
            bool textChanged = false;
            await this.Dispatcher.RunAsync(
                Windows.UI.Core.CoreDispatcherPriority.Normal,
                () =>
                {
                    textChanged = this.Secret.Text != this.previousSecret;
                });
            if (textChanged)
            {
                var tick = DateTimeOffset.UtcNow;
                await this.Dispatcher.RunAsync(
                    Windows.UI.Core.CoreDispatcherPriority.Normal,
                    () =>
                    {
                        this.previousSecret = this.Secret.Text;
                        this.Secret.IsEnabled = false;
                        this.TimeCost.IsEnabled = false;
                        this.MemoryCost.IsEnabled = false;
                        this.Parallelism.IsEnabled = false;
                        this.Type.IsEnabled = false;
                        this.HashLength.IsEnabled = false;
                        this.HashTitle.Text = string.Empty;
                        this.HashValue.Text =
                            $"Calculating hash for \"{this.previousSecret}\"...";
                        this.HashTime.Text = string.Empty;
                    });
                try
                {
                    int timeCost = 3;
                    int memoryCost = 65536;
                    int parallelism = 1;
                    Argon2Type type = Argon2Type.HybridAddressing;
                    int hashLength = 32;
                    await this.Dispatcher.RunAsync(
                        Windows.UI.Core.CoreDispatcherPriority.Normal,
                        () =>
                        {
                            if (!int.TryParse(this.TimeCost.Text, out timeCost)
                                || timeCost < 1)
                            {
                                timeCost = 3;
                                this.TimeCost.Text = "3";
                            }

                            if (!int.TryParse(this.MemoryCost.Text, out memoryCost)
                                || memoryCost < 1)
                            {
                                memoryCost = 65536;
                                this.MemoryCost.Text = "65536";
                            }

                            if (!int.TryParse(this.Parallelism.Text, out parallelism)
                                || parallelism < 1)
                            {
                                parallelism = 1;
                                this.Parallelism.Text = "1";
                            }

                            if (this.Type.SelectedIndex == 0)
                            {
                                type = Argon2Type.DataDependentAddressing;
                            }
                            else if (this.Type.SelectedIndex == 1)
                            {
                                type = Argon2Type.DataIndependentAddressing;
                            }
                            else
                            {
                                type = Argon2Type.HybridAddressing;
                                this.Type.SelectedIndex = 2;
                            }

                            if (!int.TryParse(this.HashLength.Text, out hashLength)
                                || hashLength < 1)
                            {
                                hashLength = 32;
                                this.HashLength.Text = "32";
                            }
                        });

                    var hashValue = await Task.Run(
                        () => Argon2.Hash(
                            this.previousSecret,
                            timeCost,
                            memoryCost,
                            parallelism,
                            type,
                            hashLength));
                    var hashTime =
                        ((int)(DateTimeOffset.UtcNow - tick).TotalMilliseconds) / 1000.0;
                    var hashTimeText = $"({hashTime} seconds)";
                    await this.Dispatcher.RunAsync(
                        Windows.UI.Core.CoreDispatcherPriority.Normal,
                        () =>
                        {
                            this.HashTitle.Text = $"Hash for \"{this.previousSecret}\".";
                            this.HashValue.Text = hashValue;
                            this.HashTime.Text = hashTimeText;
                        });
                }
                finally
                {
                    await this.Dispatcher.RunAsync(
                        Windows.UI.Core.CoreDispatcherPriority.Normal,
                        () =>
                        {
                            this.Secret.IsEnabled = true;
                            this.TimeCost.IsEnabled = true;
                            this.MemoryCost.IsEnabled = true;
                            this.Parallelism.IsEnabled = true;
                            this.Type.IsEnabled = true;
                            this.HashLength.IsEnabled = true;
                        });
                }
            }
        }
    }
}