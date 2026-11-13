document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("trafficForm");
    const input = document.getElementById("inputText");

    form.addEventListener("submit", function (event) {

        const trafficData = input.value.trim();

        if (trafficData === "") {
            event.preventDefault();
            alert("Please enter network traffic data!");
            return;
        }

        if (trafficData.length > 2000) {
            event.preventDefault();
            alert("Traffic data should not exceed 2000 characters!");
            return;
        }

    });

});
