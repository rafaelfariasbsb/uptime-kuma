exports.up = function (knex) {
    return knex.schema.table("user", function (table) {
        table.string("microsoft_id").nullable();
    });
};

exports.down = function (knex) {
    return knex.schema.table("user", function (table) {
        table.dropColumn("microsoft_id");
    });
};
