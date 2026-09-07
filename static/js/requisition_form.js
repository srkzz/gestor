document.addEventListener("DOMContentLoaded", function () {
    const container = document.getElementById("items-container");
    const addButton = document.getElementById("add-item-button");

    if (!container || !addButton) {
        return;
    }

    function updateItems() {
        const items = container.querySelectorAll(".requisition-item");

        items.forEach(function (item, index) {
            const number = item.querySelector(".item-number");
            const removeButton = item.querySelector(".remove-item");

            if (number) {
                number.textContent = `Material ${index + 1}`;
            }

            if (removeButton) {
                removeButton.disabled = items.length === 1;
            }
        });
    }

    addButton.addEventListener("click", function () {
        const firstItem = container.querySelector(".requisition-item");
        const newItem = firstItem.cloneNode(true);

        newItem.querySelectorAll("input").forEach(function (input) {
            if (input.name === "quantity[]") {
                input.value = "1";
            } else if (input.name === "unit[]") {
                input.value = "UN";
            } else {
                input.value = "";
            }
        });

        container.appendChild(newItem);
        updateItems();
    });

    container.addEventListener("click", function (event) {
        const removeButton = event.target.closest(".remove-item");

        if (!removeButton) {
            return;
        }

        const items = container.querySelectorAll(".requisition-item");

        if (items.length > 1) {
            removeButton.closest(".requisition-item").remove();
            updateItems();
        }
    });

    updateItems();
});
