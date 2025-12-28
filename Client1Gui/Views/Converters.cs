using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Layout;
using Avalonia.Media;

namespace Client1Gui.Views
{
    public sealed class BooleanToAlignmentConverter : IValueConverter
    {
        public static readonly BooleanToAlignmentConverter Instance = new();

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool isMe = value is bool b && b;
            return isMe ? HorizontalAlignment.Right : HorizontalAlignment.Left;
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }

    public sealed class BooleanToColorConverter : IValueConverter
    {
        public static readonly BooleanToColorConverter Instance = new();

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool isMe = value is bool b && b;
            return isMe ? Color.Parse("#2A3B5F") : Color.Parse("#2A2A2A");
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
            => throw new NotSupportedException();
    }
}
