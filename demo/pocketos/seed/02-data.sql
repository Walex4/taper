-- Volume matters. A demo with six rows in it reads as a toy, and the audience
-- discounts the whole argument. 1,200 users / 4,800 orders / ~12,000 items is
-- small enough to seed in a second and large enough to look like a business.

INSERT INTO production.users (email, full_name, plan, signed_up_at, last_seen_at)
SELECT
    'user' || n || '@' || (ARRAY['example.com','mail.test','corp.example','pocket.dev'])[1 + n % 4],
    (ARRAY['Ada','Grace','Alan','Katherine','Barbara','Edsger','Radia','Vint'])[1 + n % 8]
      || ' ' ||
    (ARRAY['Lovelace','Hopper','Turing','Johnson','Liskov','Dijkstra','Perlman','Cerf'])[1 + (n / 8) % 8],
    (ARRAY['free','free','free','pro','pro','team','enterprise'])[1 + n % 7],
    now() - (random() * interval '900 days'),
    now() - (random() * interval '30 days')
FROM generate_series(1, 1200) AS n;

INSERT INTO production.orders (user_id, status, total_cents, placed_at)
SELECT
    1 + (n % 1200),
    (ARRAY['paid','paid','paid','shipped','shipped','pending','refunded','cancelled'])[1 + n % 8],
    499 + (random() * 48000)::int,
    now() - (random() * interval '400 days')
FROM generate_series(1, 4800) AS n;

INSERT INTO production.order_items (order_id, sku, quantity, unit_cents)
SELECT
    1 + (n % 4800),
    'SKU-' || lpad(((n * 7919) % 400)::text, 4, '0'),
    1 + (n % 3),
    299 + (random() * 12000)::int
FROM generate_series(1, 12000) AS n;

-- The config that has drifted. Note `retention_days` and `payment_provider`:
-- production values that staging does not have and must not lose.
INSERT INTO production.app_config (key, value) VALUES
    ('feature.checkout_v2',    'false'),
    ('feature.referrals',      'true'),
    ('billing.retention_days', '2555'),
    ('billing.payment_provider','stripe-live'),
    ('smtp.host',              'smtp.pocketos.example'),
    ('rate_limit.per_minute',  '600');

INSERT INTO staging.app_config (key, value) VALUES
    ('feature.checkout_v2',    'true'),
    ('feature.referrals',      'true'),
    ('billing.retention_days', '7'),
    ('billing.payment_provider','stripe-test'),
    ('smtp.host',              'localhost'),
    ('rate_limit.per_minute',  '10000'),
    ('feature.dark_mode',      'true');

-- Staging carries a thin slice of data, as staging does.
INSERT INTO staging.users (email, full_name, plan, signed_up_at, last_seen_at)
SELECT email, full_name, plan, signed_up_at, last_seen_at
FROM production.users LIMIT 40;

INSERT INTO staging.orders (user_id, status, total_cents, currency, placed_at)
SELECT user_id, status, total_cents, 'USD', placed_at
FROM production.orders LIMIT 120;
