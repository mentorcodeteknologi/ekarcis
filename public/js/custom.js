"use strict";
$(document).ready(function () {
    $('.select2').select2();
    $('#categories').mouseenter(function() {
        $('.categoriesClass').show();
    });
    $('.categoriesClass').mouseleave(function() {
        $('.categoriesClass').hide();
    });

    $('.language').mouseenter(function() {
        $('.languageClass').show();
    });
    $('.languageClass').mouseleave(function() {
        $('.languageClass').hide();
    });
    $("#dropdownMenuButton").on('click',function () {
        $(".dropdownClass").toggle();
    });

    $("#dropdownScreenButton").on('click',function () {
        $(".dropdownMenuClass").toggle();
    });


});
