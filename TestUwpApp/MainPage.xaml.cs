// <copyright file="MainPage.xaml.cs" company="Isopoh">
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
// </copyright>

using System;
using Isopoh.Cryptography.SecureArray;

namespace TestUwpApp
{
    using Isopoh.Cryptography.Argon2;
    using Windows.UI.Xaml.Controls;

    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MainPage"/> class.
        /// </summary>
        public MainPage()
        {
            this.InitializeComponent();
            this.Os.Text = $"Operating System: {SecureArray.DefaultCall.Os} {IntPtr.Size * 8}-bit";
            this.Hash.Text = $"\"password\" hash: {Argon2.Hash("password")}";
        }
    }
}
