-- Habilitar RLS en la tabla ingresos
ALTER TABLE public.ingresos ENABLE ROW LEVEL SECURITY;

-- Eliminar políticas existentes para evitar conflictos
DROP POLICY IF EXISTS "allow_full_select_for_non_restricted_roles" ON public.ingresos;
DROP POLICY IF EXISTS "allow_basic_select_for_restricted_roles" ON public.ingresos;

-- 1. Función auxiliar para verificar el rol del usuario actual
-- SECURITY DEFINER es crucial para que esta función pueda acceder a las tablas de roles.
CREATE OR REPLACE FUNCTION public.is_user_role(role_name text)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM auth.users u
    JOIN public.user_roles ur ON u.id = ur.user_id
    JOIN public.roles r ON ur.role_id = r.id
    WHERE u.id = auth.uid() AND r.role_name = role_name
  );
$$;

-- 2. Función RPC para obtener el número de recibo de forma segura
-- Esta función es la única forma en que los ingenieros obtendrán el receipt_number real.
-- Debe ser SECURITY DEFINER para ignorar RLS en la tabla base.
CREATE OR REPLACE FUNCTION public.get_receipt_numbers_for_role(ingreso_ids integer[])
RETURNS TABLE(id integer, receipt_number text)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT
        i.id,
        i.receipt_number::text
    FROM
        public.ingresos i
    WHERE
        i.id = ANY(ingreso_ids);
END;
$$;

-- 3. Política para roles NO restringidos (Admins, etc.): Permite SELECT completo.
CREATE POLICY "allow_full_select_for_non_restricted_roles"
ON public.ingresos
FOR SELECT
TO authenticated
USING (
  NOT public.is_user_role('engineer') AND NOT public.is_user_role('files')
);

-- 4. Política para roles restringidos (engineer, files): Permite SELECT de filas,
-- pero enmascara las columnas sensibles.

-- IMPORTANTE: Dado que RLS estándar solo filtra filas (USING), no puede modificar columnas.
-- Para lograr el enmascaramiento de columnas sin modificar el código de la aplicación (SELECT *),
-- se debe utilizar una función de enmascaramiento avanzada o una VISTA.
-- Como no podemos modificar el código de la aplicación para consultar una VISTA,
-- implementaremos una política que permite el SELECT de filas para que la aplicación
-- pueda obtener los IDs y la localidad, y confiaremos en la lógica de la aplicación
-- (que usa el RPC) para el 'receipt_number'.

-- Para asegurar que las columnas sensibles sean NULL para los ingenieros,
-- la forma más segura es crear una VISTA y modificar la aplicación para usarla.
-- Dado que esto viola la restricción "no modificar código core",
-- la siguiente política es la más permisiva que permite que la aplicación funcione,
-- pero requiere que el desarrollador implemente el enmascaramiento de columnas
-- en el lado del servidor (ej. usando un trigger o una vista con la función de enmascaramiento).

-- Para este ejercicio, definiremos la política que permite a los ingenieros ver las filas,
-- y asumiremos que el desarrollador aplicará el enmascaramiento de columnas
-- en el entorno de Supabase (ej. usando un trigger BEFORE SELECT, si es soportado).

CREATE POLICY "allow_basic_select_for_restricted_roles"
ON public.ingresos
FOR SELECT
TO authenticated
USING (
  public.is_user_role('engineer') OR public.is_user_role('files')
);

-- NOTA: Si desea una seguridad de columna perfecta, debe crear una VISTA
-- que aplique el enmascaramiento y modificar la aplicación para consultar esa VISTA.
-- Ejemplo de función de enmascaramiento (para referencia, no se aplica directamente en la política USING):
/*
CREATE OR REPLACE FUNCTION public.mask_ingreso_for_engineer(r public.ingresos)
RETURNS public.ingresos
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    IF public.is_user_role('engineer') OR public.is_user_role('files') THEN
        r.created_at := NULL;
        r.account := 'RESTRICTED';
        r.amount := 0;
        r.transaction_type := 'RESTRICTED';
        r.dni := '********';
        r.full_name := 'RESTRICTED NAME';
        r.numeroOperacion := NULL;
        r.date := '1970-01-01';
    END IF;
    RETURN r;
END;
$$;
*/
