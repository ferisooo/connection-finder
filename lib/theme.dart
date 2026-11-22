// The pink & black look of Connection Finder.

import 'dart:math' as math;

import 'package:material_ui/material_ui.dart';

import 'models.dart';

abstract final class AppColors {
  static const Color bg = Color(0xFF09090C);
  static const Color panel = Color(0xFF111117);
  static const Color card = Color(0xFF15141C);
  static const Color cardHigh = Color(0xFF1C1A25);
  static const Color border = Color(0xFF2A2433);
  static const Color borderSoft = Color(0xFF211D29);

  static const Color pink = Color(0xFFFF4FA3);
  static const Color hotPink = Color(0xFFFF2E88);
  static const Color softPink = Color(0xFFFFA8D2);
  static const Color blush = Color(0xFFFFD9EC);
  static const Color magenta = Color(0xFFC2187A);
  static const Color danger = Color(0xFFFF3366);

  static const Color text = Color(0xFFF8EEF4);
  static const Color muted = Color(0xFFA898A5);
  static const Color faint = Color(0xFF6F6372);
  static const Color safe = Color(0xFFB8AACB);

  static const LinearGradient pinkGradient = LinearGradient(
    colors: [Color(0xFFFF6DB5), Color(0xFFD61F86)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static Color forLevel(RiskLevel level) => switch (level) {
        RiskLevel.safe => safe,
        RiskLevel.suspicious => pink,
        RiskLevel.dangerous => danger,
      };

  static Color forRating(AiRating rating) => switch (rating) {
        AiRating.safe => safe,
        AiRating.suspicious => pink,
        AiRating.dangerous => danger,
        AiRating.unknown => muted,
      };
}

const String monoFont = 'Consolas';
const List<String> monoFallback = [
  'Cascadia Mono',
  'Courier New',
  'DejaVu Sans Mono',
  'monospace',
];

TextStyle mono(double size,
        {Color color = AppColors.text, FontWeight weight = FontWeight.w400}) =>
    TextStyle(
      fontFamily: monoFont,
      fontFamilyFallback: monoFallback,
      fontSize: size,
      color: color,
      fontWeight: weight,
      height: 1.3,
    );

ThemeData buildTheme() {
  const scheme = ColorScheme.dark(
    primary: AppColors.pink,
    onPrimary: Colors.white,
    secondary: AppColors.softPink,
    onSecondary: AppColors.bg,
    surface: AppColors.card,
    onSurface: AppColors.text,
    error: AppColors.danger,
    outline: AppColors.border,
  );
  final base = ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    colorScheme: scheme,
    scaffoldBackgroundColor: AppColors.bg,
    canvasColor: AppColors.panel,
    splashFactory: InkSparkle.splashFactory,
  );
  final textTheme = atLeast15(base.textTheme).apply(
    bodyColor: AppColors.text,
    displayColor: AppColors.text,
  );
  final label = textTheme.labelLarge ?? const TextStyle();
  final body = textTheme.bodyMedium ?? const TextStyle();
  return base.copyWith(
    textTheme: textTheme,
    iconTheme: const IconThemeData(color: AppColors.softPink),
    dividerTheme:
        const DividerThemeData(color: AppColors.borderSoft, thickness: 1),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: AppColors.cardHigh,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      textStyle: body.copyWith(color: AppColors.text, fontSize: 15),
      waitDuration: const Duration(milliseconds: 400),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: AppColors.cardHigh,
      contentTextStyle: body.copyWith(color: AppColors.text, fontSize: 15),
      actionTextColor: AppColors.pink,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: const BorderSide(color: AppColors.pink, width: 1),
      ),
      width: 560,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AppColors.panel,
      hintStyle: const TextStyle(color: AppColors.faint),
      helperStyle: const TextStyle(color: AppColors.muted, fontSize: 15),
      errorStyle: const TextStyle(color: AppColors.danger, fontSize: 15),
      labelStyle: const TextStyle(color: AppColors.muted),
      floatingLabelStyle: const TextStyle(color: AppColors.pink),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: AppColors.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: AppColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: AppColors.pink, width: 1.4),
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: AppColors.pink,
        foregroundColor: Colors.white,
        disabledBackgroundColor: AppColors.cardHigh,
        disabledForegroundColor: AppColors.faint,
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: label.copyWith(fontWeight: FontWeight.w700, fontSize: 15),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.softPink,
        side: const BorderSide(color: AppColors.border),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        textStyle: label.copyWith(fontWeight: FontWeight.w700, fontSize: 15),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: AppColors.softPink,
        textStyle: label.copyWith(fontWeight: FontWeight.w700, fontSize: 15),
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((s) =>
          s.contains(WidgetState.selected) ? Colors.white : AppColors.muted),
      trackColor: WidgetStateProperty.resolveWith((s) =>
          s.contains(WidgetState.selected) ? AppColors.pink : AppColors.cardHigh),
      trackOutlineColor: WidgetStateProperty.resolveWith((s) =>
          s.contains(WidgetState.selected) ? AppColors.pink : AppColors.border),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: AppColors.panel,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(22),
        side: const BorderSide(color: AppColors.border),
      ),
    ),
    progressIndicatorTheme:
        const ProgressIndicatorThemeData(color: AppColors.pink),
    scrollbarTheme: ScrollbarThemeData(
      thumbColor: WidgetStateProperty.all(AppColors.border),
      radius: const Radius.circular(8),
      thickness: WidgetStateProperty.all(8),
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: AppColors.cardHigh,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: AppColors.border),
      ),
    ),
  );
}

/// Makes every text style in [t] at least 15px, as the app's minimum.
TextTheme atLeast15(TextTheme t) {
  TextStyle? fix(TextStyle? s) =>
      s?.copyWith(fontSize: math.max(15, s.fontSize ?? 15));
  return t.copyWith(
    displayLarge: fix(t.displayLarge),
    displayMedium: fix(t.displayMedium),
    displaySmall: fix(t.displaySmall),
    headlineLarge: fix(t.headlineLarge),
    headlineMedium: fix(t.headlineMedium),
    headlineSmall: fix(t.headlineSmall),
    titleLarge: fix(t.titleLarge),
    titleMedium: fix(t.titleMedium),
    titleSmall: fix(t.titleSmall),
    bodyLarge: fix(t.bodyLarge),
    bodyMedium: fix(t.bodyMedium),
    bodySmall: fix(t.bodySmall),
    labelLarge: fix(t.labelLarge),
    labelMedium: fix(t.labelMedium),
    labelSmall: fix(t.labelSmall),
  );
}
