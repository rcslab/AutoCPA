package bcpi;

import java.util.Objects;

/**
 * Metadata about a struct field reference.
 */
public class FieldReference {
	private final Field field;
	private final boolean arrayAccess;
	private final boolean isRead;

	FieldReference(Field field, boolean arrayAccess, boolean isRead) {
		this.field = field;
		this.arrayAccess = arrayAccess;
		this.isRead = isRead;
	}

	/** The field being accessed. */
	public Field getField() {
		return this.field;
	}

	/** Whether this field was accessed as part of an array. */
	public boolean isArrayAccess() {
		return this.arrayAccess;
	}

	/** Whether this access was a read access. */
	public boolean isRead() {
		return this.isRead;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		} else if (!(obj instanceof FieldReference)) {
			return false;
		}

		FieldReference other = (FieldReference) obj;
		return this.field.equals(other.field)
			&& this.arrayAccess == other.arrayAccess
			&& this.isRead == other.isRead;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.field, this.arrayAccess, this.isRead);
	}

	@Override
	public String toString() {
		String parent = this.field.getParent().getName();
		String array = this.arrayAccess ? "[]" : "";
		String name = this.field.getFieldName();
		String rw = this.isRead ? "R" : "W";
		return String.format("%s%s::%s(%s)", parent, array, name, rw);
	}
}
