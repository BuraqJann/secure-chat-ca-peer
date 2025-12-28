using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Threading;
using Client2Gui.ViewModels;

namespace Client2Gui.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();

            AttachedToVisualTree += (_, __) =>
                Dispatcher.UIThread.Post(ScrollToBottom, DispatcherPriority.Background);
        }

        private void MessageBox_KeyUp(object? sender, KeyEventArgs e)
        {
            if (DataContext is not MainViewModel vm) return;

            if (e.Key == Key.Enter && (e.KeyModifiers & KeyModifiers.Shift) == 0)
            {
                e.Handled = true;
                vm.SendCommand.Execute(null);
                Dispatcher.UIThread.Post(ScrollToBottom, DispatcherPriority.Background);
            }
        }

        private void ScrollToBottom()
        {
            var sv = this.FindControl<ScrollViewer>("ChatScroll");
            if (sv == null) return;

            var y = Math.Max(0, sv.Extent.Height - sv.Viewport.Height);
            sv.Offset = new Vector(0, y);
        }
    }
}
