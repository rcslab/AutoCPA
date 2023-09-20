package bcpi;

import bcpi.type.BcpiStruct;
import bcpi.type.Field;
import bcpi.type.Layout;

import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * ABI constraints on struct layouts.
 */
public class StructAbiConstraints {
	private final List<Field> fields;
	private final Map<String, Field> map;
	private final int[] fixed;
	private final int[] groups;
	private final BitSet[] groupOrdering;

	public StructAbiConstraints(BcpiStruct struct) {
		this.fields = struct.getFields();

		var nFields = this.fields.size();
		this.map = new HashMap<>();
		this.fixed = new int[nFields];
		this.groups = new int[nFields];
		this.groupOrdering = new BitSet[nFields];
		Arrays.fill(this.fixed, -1);
		Arrays.fill(this.groups, -1);

		for (int i = 0; i < nFields; ++i) {
			var field = this.fields.get(i);
			var name = field.getName();
			this.map.put(name, field);

			// TODO: Ghidra should expose something more reliable
			if (name.startsWith("super_")) {
				this.fixed[i] = i;
			}
		}
	}

	private int getIndex(String name) {
		var field = this.map.get(name);
		if (field == null) {
			throw new IllegalArgumentException("No such field " + field);
		}
		return field.getOriginalIndex();
	}

	private void setGroup(int index, int group) {
		int prev = this.groups[index];
		if (prev != -1) {
			var field = this.fields.get(index);
			throw new IllegalArgumentException(String.format("Conflicting groups %d and %d for %s", prev, group, field));
		}
		this.groups[index] = group;
	}

	/** Set the group constraint for a field. */
	public void setGroup(String name, int group) {
		Objects.checkIndex(group, this.groupOrdering.length);
		setGroup(getIndex(name), group);
	}

	/** Set the group constraint for a range of fields. */
	public void setRangeGroup(String from, String to, int group) {
		int start = getIndex(from);
		int end = getIndex(to);
		Objects.checkFromToIndex(start, end, this.groups.length);
		for (int i = start; i <= end; ++i) {
			setGroup(i, group);
		}
	}

	/** Constrain the relative orders of two groups. */
	public void orderGroups(int before, int after) {
		var order = this.groupOrdering;
		Objects.checkIndex(before, order.length);
		Objects.checkIndex(after, order.length);

		var bits = order[before];
		if (bits == null) {
			bits = order[before] = new BitSet(order.length);
		}
		bits.set(after);
	}

	/** Set a fixed position for a field. */
	public void setFixed(String name, int index) {
		int i = getIndex(name);
		this.fixed[i] = index;
	}

	/**
	 * @return Whether the given field has its position fixed.
	 */
	public boolean isFixed(Field field) {
		return this.fixed[field.getOriginalIndex()] >= 0;
	}

	/**
	 * @return Whether this layout satisfies the constraints.
	 */
	public boolean check(Layout layout) {
		if (!checkFixed(layout)) {
			return false;
		}

		if (!checkGroups(layout)) {
			return false;
		}

		return true;
	}

	/** Check fixed field constraints. */
	private boolean checkFixed(Layout layout) {
		for (var field : layout.getFields()) {
			int expected = this.fixed[field.getOriginalIndex()];
			if (expected >= 0 && field.getIndex() != expected) {
				return false;
			}
		}

		return true;
	}

	/** Check group constraints. */
	private boolean checkGroups(Layout layout) {
		var fields = layout.getFields();
		var groups = new int[fields.size()];
		for (int i = 0; i < groups.length; ++i) {
			groups[i] = getGroup(fields.get(i));
		}

		// Collapse consecutive duplicates
		int length = 0;
		for (int i = 1; i < groups.length; ++i) {
			if (groups[i] != groups[length]) {
				++length;
				groups[length] = groups[i];
			}
		}

		for (int i = 0; i < length; ++i) {
			if (groups[i] < 0) {
				continue;
			}

			for (int j = i + 1; j < length; ++j) {
				if (groups[j] < 0) {
					continue;
				}

				if (!checkGroupOrdering(groups[i], groups[j])) {
					return false;
				}
			}
		}

		return true;
	}

	private int getGroup(Field field) {
		return this.groups[field.getOriginalIndex()];
	}

	/** Check the relative order of two groups. */
	private boolean checkGroupOrdering(int before, int after) {
		if (before == after) {
			// Discontiguous group
			return false;
		}

		// Check that we don't have an after<before constraint
		var bits = this.groupOrdering[after];
		if (bits == null) {
			return true;
		} else {
			return !bits.get(before);
		}
	}
}
